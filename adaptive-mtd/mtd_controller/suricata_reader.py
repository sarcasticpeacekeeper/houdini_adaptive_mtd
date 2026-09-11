"""Suricata EVE JSON reader.

Tails /var/log/suricata/eve.json, parses alert events, normalizes them to
Event objects, and yields them to the controller.

EVE JSON is one JSON object per line. We only care about `event_type: alert`.
Severity mapping (Suricata numeric, lower = worse):
    1 -> high   (web-application-attack, attempted-admin)
    2 -> medium (attempted-recon)
    3 -> low    (everything else)

NEW (redesign): we also extract src_ip from the alert so the policy can
flag the source as an attacker and the controller can redirect that
source's HTTPS traffic to the honeypot.
"""

from __future__ import annotations

import json
import time
from typing import Iterator

from .policy import Event


def _severity_for(alert: dict) -> str:
    sev = alert.get("severity", 3)
    if sev == 1:
        return "high"
    if sev == 2:
        return "medium"
    return "low"


def parse_eve_line(line: str) -> Event | None:
    """Parse one EVE JSON line. Returns an Event if it's an alert, else None."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if obj.get("event_type") != "alert":
        return None
    alert = obj.get("alert", {})
    # src_ip is at the top level of the EVE alert object, not inside `alert`
    src_ip = obj.get("src_ip") or obj.get("src_addr")
    return Event(
        source="suricata",
        severity=_severity_for(alert),
        message=alert.get("signature", "unknown suricata alert"),
        src_ip=src_ip,
        sid=alert.get("signature_id"),
        timestamp=time.time(),
    )


def tail_events(path: str, poll_interval: float = 0.5) -> Iterator[Event]:
    """Generator that tails the EVE JSON file and yields alert Events.

    Handles file rotation (Suricata rotates eve.json) by reopening if the
    file shrinks or disappears.
    """
    import os
    inode = None
    f = None
    while True:
        try:
            if not os.path.exists(path):
                time.sleep(poll_interval)
                continue
            if f is None:
                f = open(path, "r", encoding="utf-8")
                f.seek(0, os.SEEK_END)
                inode = os.fstat(f.fileno()).st_ino
            # Detect rotation: inode changed
            try:
                current_inode = os.stat(path).st_ino
            except FileNotFoundError:
                f.close()
                f = None
                inode = None
                time.sleep(poll_interval)
                continue
            if current_inode != inode:
                f.close()
                f = open(path, "r", encoding="utf-8")
                inode = current_inode
            line = f.readline()
            if line:
                ev = parse_eve_line(line)
                if ev is not None:
                    yield ev
            else:
                time.sleep(poll_interval)
        except Exception:
            # Best-effort: on any error, wait and retry rather than die
            time.sleep(poll_interval)
