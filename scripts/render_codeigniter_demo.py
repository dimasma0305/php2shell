#!/usr/bin/env python3
"""Render the verified CodeIgniter PoC with a pinned VHS container."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


VHS_IMAGE = (
    "ghcr.io/charmbracelet/vhs@"
    "sha256:ea49a6a1c529be83153e88321892b5585964418f0b9055e8c1e0d732194234a3"
)
PROOF_MARKER = "PROOF: callback path="
OUTPUTS = (
    Path("docs/demo/php2shell-codeigniter.gif"),
    Path("docs/demo/php2shell-codeigniter.mp4"),
    Path("docs/demo/php2shell-codeigniter.txt"),
    Path("docs/demo/php2shell-codeigniter-proof.txt"),
)


def command(args: list[str], root: Path, *, check: bool = True) -> int:
    completed = subprocess.run(args, cwd=root, check=False)
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(args)}"
        )
    return completed.returncode


def remove_outputs(root: Path) -> None:
    for relative in OUTPUTS:
        (root / relative).unlink(missing_ok=True)


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


def run_poc(root: Path, lab_url: str) -> bool:
    proof_path = root / OUTPUTS[3]
    with proof_path.open("w", encoding="utf-8", newline="") as proof:
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "poc.py",
                    "--url",
                    lab_url,
                    "--retries",
                    "1",
                ],
                cwd=root,
                stdout=proof,
                stderr=subprocess.STDOUT,
                timeout=600,
                check=False,
            )
        except subprocess.TimeoutExpired:
            proof.write("\nPOC_TIMEOUT\n")
            return False
    output = proof_path.read_text(encoding="utf-8", errors="replace")
    return completed.returncode == 0 and PROOF_MARKER in output


def render_once(root: Path) -> bool:
    volume = f"{root}:/vhs"
    command(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            volume,
            "-w",
            "/vhs",
            VHS_IMAGE,
            "docs/demo/codeigniter.tape",
        ],
        root,
    )
    transcript = (root / OUTPUTS[2]).read_text(encoding="utf-8", errors="replace")
    proof_log = (root / OUTPUTS[3]).read_text(encoding="utf-8", errors="replace")
    return PROOF_MARKER in transcript and PROOF_MARKER in proof_log


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
            if run_poc(root, lab_url) and render_once(root):
                success = True
                print("[+] VHS transcript contains fresh callback proof", flush=True)
                for output in OUTPUTS:
                    print(f"[+] {output}", flush=True)
                return 0
            print("[!] no proof on this master; retrying from a fresh container", flush=True)
    finally:
        if not args.keep_lab:
            command(compose_command + ["down", "--remove-orphans"], root, check=False)
        if not success:
            remove_outputs(root)

    print("RCE proof was not observed; no demo artifacts were retained", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
