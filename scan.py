#!/usr/bin/env python3
"""Passive multi-asset version triage for CVE-2026-109618/109619.

This scanner sends only ordinary bounded HTTP HEAD/GET requests. It never
imports the exploit, uploads data, writes a remote file, or tests RCE/DoS.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

MAX_BODY = 64 * 1024
MAX_WORKERS = 32
USER_AGENT = "php2shell-passive-scan/1.0"
PHP_RE = re.compile(r"\bPHP/?(?:-|\s)?v?(\d+)\.(\d+)\.(\d+)\b", re.I)
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}


@dataclass(frozen=True)
class Result:
    asset: str
    status: str
    observed: str
    detail: str
    elapsed_ms: int


def load_assets(path: Path) -> list[str]:
    seen: set[str] = set()
    assets: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"{path}:{number}: expected an http:// or https:// URL")
        if value not in seen:
            seen.add(value)
            assets.append(value)
    if not assets:
        raise ValueError(f"{path}: no assets found")
    return assets


def version_from(headers: Iterable[tuple[str, str]], body: bytes) -> tuple[int, int, int] | None:
    text = "\n".join(f"{key}: {value}" for key, value in headers)
    text += "\n" + body.decode("latin-1", "replace")
    match = PHP_RE.search(text)
    return tuple(map(int, match.groups())) if match else None


def classify(version: tuple[int, int, int] | None, headers: list[tuple[str, str]], body: bytes) -> tuple[str, str, str]:
    evidence = "\n".join(f"{k}: {v}" for k, v in headers).lower()
    sample = body[:4096].decode("latin-1", "replace").lower()
    if version:
        label = ".".join(map(str, version))
        boundary = FIXED.get(version[:2])
        if boundary is None:
            return "RUNTIME_DETECTED_VERSION_UNASSESSED", f"PHP/{label}", "version is outside the advisory's supported release lines"
        if version < boundary:
            return "AFFECTED_VERSION_OBSERVED", f"PHP/{label}", f"below fixed release {'.'.join(map(str, boundary))}"
        return "PATCHED_VERSION_OBSERVED", f"PHP/{label}", f"at or above fixed release {'.'.join(map(str, boundary))}"
    php_signal = any(token in evidence or token in sample for token in ("phpsessid", "wordpress", "mediawiki", "dokuwiki", "joomla", "codeigniter", "x-powered-by: php"))
    if php_signal:
        return "RUNTIME_DETECTED_VERSION_HIDDEN", "PHP/application signal", "PHP version was not disclosed"
    return "NO_RUNTIME_EVIDENCE", "none", "reachable HTTP service did not disclose a PHP signal"


def request(asset: str, timeout: float) -> Result:
    started = time.monotonic()
    parsed = urlsplit(asset)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.8,*/*;q=0.1", "Connection": "close"}
    try:
        response_headers: list[tuple[str, str]] = []
        body = b""
        code = 0
        for method in ("HEAD", "GET"):
            connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            kwargs = {"timeout": timeout}
            if parsed.scheme == "https":
                kwargs["context"] = ssl.create_default_context()
            connection = connection_cls(parsed.hostname, port, **kwargs)
            try:
                connection.request(method, path, headers=headers)
                response = connection.getresponse()
                code = response.status
                response_headers = response.getheaders()
                if method == "GET":
                    body = response.read(MAX_BODY + 1)[:MAX_BODY]
                else:
                    response.read(MAX_BODY + 1)
            finally:
                connection.close()
            if method == "HEAD" and code in {405, 501}:
                continue
            break
        version = version_from(response_headers, body)
        status, observed, detail = classify(version, response_headers, body)
        detail = f"HTTP {code}; {detail}"
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        status, observed, detail = "UNREACHABLE", "none", f"{type(exc).__name__}: {exc}"
    return Result(asset, status, observed, detail, round((time.monotonic() - started) * 1000))


def safe_request(asset: str, timeout: float) -> Result:
    try:
        return request(asset, timeout)
    except Exception as exc:  # keep one malformed endpoint from aborting the asset set
        return Result(asset, "ERROR", "none", f"{type(exc).__name__}: {exc}", 0)


def print_table(results: list[Result]) -> None:
    columns = [
        ("ASSET", [r.asset for r in results]),
        ("STATUS", [r.status for r in results]),
        ("OBSERVED", [r.observed for r in results]),
        ("DETAIL", [r.detail for r in results]),
    ]
    widths = [min(max(len(title), *(len(v) for v in values)), cap) for (title, values), cap in zip(columns, (42, 36, 28, 58))]
    def row(values: list[str]) -> str:
        return "  ".join(value[:width].ljust(width) for value, width in zip(values, widths)).rstrip()
    print(row([title for title, _ in columns]))
    print(row(["-" * width for width in widths]))
    for result in results:
        print(row([result.asset, result.status, result.observed, result.detail]))


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive multi-asset version triage; does not test exploitation")
    parser.add_argument("--assets", required=True, type=Path, help="newline-delimited http(s) URLs")
    parser.add_argument("--workers", type=int, default=4, help=f"concurrent workers (1-{MAX_WORKERS})")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-request timeout in seconds")
    parser.add_argument("--format", choices=("table", "jsonl"), default="table")
    args = parser.parse_args()
    if not 1 <= args.workers <= MAX_WORKERS:
        parser.error(f"--workers must be between 1 and {MAX_WORKERS}")
    if not 0 < args.timeout <= 60:
        parser.error("--timeout must be greater than 0 and at most 60")
    try:
        assets = load_assets(args.assets)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    info_stream = sys.stderr if args.format == "jsonl" else sys.stdout
    print(f"[*] loaded {len(assets)} unique assets from {args.assets}", file=info_stream)
    print("[*] passive mode: bounded HEAD/GET only; no exploit or availability test", file=info_stream)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(safe_request, asset, args.timeout): index for index, asset in enumerate(assets)}
        indexed = [(futures[future], future.result()) for future in concurrent.futures.as_completed(futures)]
    results = [result for _, result in sorted(indexed)]
    if args.format == "jsonl":
        for result in results:
            print(json.dumps(asdict(result), sort_keys=True))
    else:
        print_table(results)
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    print("[*] summary " + " ".join(f"{key}={counts[key]}" for key in sorted(counts)), file=info_stream)
    return 0


if __name__ == "__main__":
    sys.exit(main())
