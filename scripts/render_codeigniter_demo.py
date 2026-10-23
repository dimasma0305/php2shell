#!/usr/bin/env python3
"""Record a live CodeIgniter lab exploit with a pinned VHS container."""

from __future__ import annotations

import argparse
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


VHS_IMAGE = (
    "ghcr.io/charmbracelet/vhs@"
    "sha256:ea49a6a1c529be83153e88321892b5585964418f0b9055e8c1e0d732194234a3"
)
PROOF_MARKER = "PROOF: callback path="
LIVE_COMMAND = (
    "python3 -u poc.py --url http://127.0.0.1:18087/ --retries 1"
)
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
RECORDER_CONTAINER = "php2shell-vhs-live"
OUTPUTS = (
    Path("docs/demo/php2shell-codeigniter.gif"),
    Path("docs/demo/php2shell-codeigniter.mp4"),
    Path("docs/demo/php2shell-codeigniter.txt"),
    Path("docs/demo/php2shell-codeigniter-proof.txt"),
)


def command(
    args: list[str], root: Path, *, check: bool = True, quiet: bool = False
) -> int:
    completed = subprocess.run(
        args,
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(args)}"
        )
    return completed.returncode


def remove_outputs(root: Path) -> None:
    for relative in OUTPUTS:
        (root / relative).unlink(missing_ok=True)


def clean_proof_output(output: str) -> str:
    plain = ANSI_ESCAPE.sub("", output).replace("\r", "")
    start = plain.find("[*] fingerprint status=")
    marker = plain.find(PROOF_MARKER, start)
    if start < 0 or marker < 0:
        raise RuntimeError("live output does not contain a complete proof")
    end = plain.find("\n", marker)
    if end < 0:
        end = len(plain)
    return plain[start:end].rstrip() + "\n"


def wait_for_lab(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.5)
    raise RuntimeError(f"lab did not become ready within {timeout:.0f}s: {url}")


def render_once(root: Path) -> bool:
    tape = (root / "docs/demo/codeigniter.tape").read_text(encoding="utf-8")
    if LIVE_COMMAND not in tape:
        raise RuntimeError("VHS tape and documented live command have diverged")
    volume = f"{root}:/vhs"
    command(
        ["docker", "rm", "-f", RECORDER_CONTAINER],
        root,
        check=False,
        quiet=True,
    )
    status = command(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            RECORDER_CONTAINER,
            "--network",
            "codeigniter_default",
            "-p",
            "8000:8000",
            "-v",
            volume,
            "-w",
            "/vhs",
            VHS_IMAGE,
            "docs/demo/codeigniter.tape",
        ],
        root,
        check=False,
    )
    if status:
        return False
    proof_path = root / OUTPUTS[3]
    if not proof_path.is_file():
        return False
    proof_log = proof_path.read_text(encoding="utf-8", errors="replace")
    if PROOF_MARKER not in proof_log:
        return False
    proof_log = clean_proof_output(proof_log)
    proof_path.write_text(proof_log, encoding="utf-8", newline="\n")
    transcript = f"$ {LIVE_COMMAND}\n{proof_log}"
    (root / OUTPUTS[2]).write_text(transcript, encoding="utf-8", newline="\n")
    return PROOF_MARKER in transcript


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a self-verified CodeIgniter RCE demo with VHS"
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=12,
        help="maximum fresh Apache masters to try (default: 12)",
    )
    parser.add_argument(
        "--keep-lab",
        action="store_true",
        help="leave the final Compose lab running",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.attempts < 1:
        raise SystemExit("--attempts must be positive")

    root = Path(__file__).resolve().parents[1]
    compose = root / "lab/8.4.26/codeigniter/compose.yaml"
    compose_command = ["docker", "compose", "-f", str(compose)]
    lab_url = "http://127.0.0.1:18087/"

    command(["docker", "version", "--format", "{{.Server.Version}}"], root)
    remove_outputs(root)
    success = False
    try:
        for attempt in range(1, args.attempts + 1):
            print(f"[*] fresh CodeIgniter master {attempt}/{args.attempts}", flush=True)
            command(compose_command + ["down", "--remove-orphans"], root)
            command(compose_command + ["up", "-d", "--build"], root)
            wait_for_lab(lab_url)
            remove_outputs(root)
            if render_once(root):
                success = True
                print("[+] live VHS run contains fresh callback proof", flush=True)
                for output in OUTPUTS:
                    print(f"[+] {output}", flush=True)
                return 0
            print("[!] no proof on this master; retrying from a fresh container", flush=True)
    finally:
        command(
            ["docker", "rm", "-f", RECORDER_CONTAINER],
            root,
            check=False,
            quiet=True,
        )
        if not args.keep_lab:
            command(compose_command + ["down", "--remove-orphans"], root, check=False)
        if not success:
            remove_outputs(root)

    print("RCE proof was not observed; no demo artifacts were retained", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
