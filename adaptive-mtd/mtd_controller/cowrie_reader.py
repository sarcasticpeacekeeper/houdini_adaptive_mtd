"""Cowrie event reader.

Tails /var/log/cowrie/cowrie.json (rsyslog-shipped from the honeypot to the
sensor), parses events, normalizes them to Event objects.

Cowrie JSON is one JSON object per line. We care about eventids:
    cowrie.login.failed   -> +bump_honeypot
    cowrie.login.success  -> +bump_honeypot (attacker got in, even to decoy)
    cowrie.command.input  -> +bump_honeypot
    cowrie.session.connect -> +bump_honeypot
"""

from __future__ import annotations

import json
import time
from typing import Iterator

from .policy import Event


COWRIE_EVENTS_OF_INTEREST = {
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.connect",
}


def parse_cowrie_line(line: str) -> Event | None:
    """Parse one Cowrie JSON line. Returns an Event if interesting, else None.

    The rsyslog forwarder wraps the cowrie JSON in a syslog prefix; we strip
    that by finding the first '{' and parsing from there.
    """
    line = line.strip()
    if not line:
        return None
    # Strip syslog prefix if present (rsyslog ships "<pri>timestamp host tag: {json}")
    brace = line.find("{")
    if brace > 0:
        line = line[brace:]
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    eventid = obj.get("eventid")
    if eventid not in COWRIE_EVENTS_OF_INTEREST:
        return None
    severity = "high" if eventid == "cowrie.login.success" else "medium"
    return Event(
        source="cowrie",
        severity=severity,
        message=f"cowrie: {eventid} from {obj.get('src_ip', '?')}",
        eventid=eventid,
        timestamp=time.time(),
    )


def tail_events(path: str, poll_interval: float = 0.5) -> Iterator[Event]:
    """Generator that tails the Cowrie JSON file and yields Events.

    Same rotation handling as suricata_reader.
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
                ev = parse_cowrie_line(line)
                if ev is not None:
                    yield ev
            else:
                time.sleep(poll_interval)
        except Exception:
            time.sleep(poll_interval)
