"""Surface state — what's currently public, the rotation history, and the
set of source IPs currently being redirected to the honeypot.

The controller writes state.json on every rotation / attacker change;
the dashboard reads it on every poll. The client loop also reads it
(via the dashboard API) to "follow the surface."
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List


@dataclass
class RotationEvent:
    timestamp: float
    old_vip: str
    new_vip: str
    old_ssh_port: int
    new_ssh_port: int
    old_https_port: int
    new_https_port: int
    threat_level: float
    t_eff: float
    reason: str  # e.g. "scheduled", "honeypot", "suricata:9000001"


@dataclass
class AttackerEntry:
    """A source IP that has been flagged as an attacker and is being
    redirected to the honeypot's dummy website."""
    src_ip: str
    flagged_at: float
    trigger_sid: int          # Suricata SID that triggered the redirect
    trigger_message: str      # human-readable trigger description
    redirect_target: str      # honeypot IP (e.g. "172.16.10.20")


@dataclass
class SurfaceState:
    current_vip: str
    current_ssh_port: int
    current_https_port: int
    threat_level: float = 0.0
    t_eff: float = 60.0
    mtd_enabled: bool = False
    last_rotation: float = 0.0
    rotation_count: int = 0
    history: List[RotationEvent] = field(default_factory=list)
    # NEW: source IPs currently redirected to the honeypot (sticky for the demo)
    attackers: Dict[str, AttackerEntry] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "SurfaceState":
        if not path.exists():
            return cls(current_vip="", current_ssh_port=0, current_https_port=0)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        history = [RotationEvent(**h) for h in data.pop("history", [])]
        attackers = {
            ip: AttackerEntry(**e) for ip, e in data.pop("attackers", {}).items()
        }
        return cls(history=history, attackers=attackers, **data)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = asdict(self)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def record_rotation(self, event: RotationEvent, rotation_log: Path) -> None:
        """Append to in-memory history (capped) and append to the rotation log file."""
        self.history.append(event)
        if len(self.history) > 100:
            self.history = self.history[-100:]
        self.last_rotation = event.timestamp
        self.rotation_count += 1
        # Append to the on-disk rotation log (one JSON object per line)
        rotation_log.parent.mkdir(parents=True, exist_ok=True)
        with open(rotation_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event)) + "\n")

    def add_attacker(self, src_ip: str, sid: int, message: str, honeypot_ip: str) -> None:
        """Flag a source IP as an attacker. Sticky for the rest of the demo."""
        if src_ip in self.attackers:
            return  # already redirected
        self.attackers[src_ip] = AttackerEntry(
            src_ip=src_ip,
            flagged_at=time.time(),
            trigger_sid=sid,
            trigger_message=message,
            redirect_target=honeypot_ip,
        )

    def is_attacker(self, src_ip: str) -> bool:
        return src_ip in self.attackers

    def to_api_dict(self) -> dict:
        """Compact dict for the dashboard API."""
        return {
            "current_vip": self.current_vip,
            "current_ssh_port": self.current_ssh_port,
            "current_https_port": self.current_https_port,
            "threat_level": round(self.threat_level, 2),
            "t_eff": round(self.t_eff, 2),
            "mtd_enabled": self.mtd_enabled,
            "last_rotation": self.last_rotation,
            "rotation_count": self.rotation_count,
            "history": [asdict(h) for h in self.history[-20:]],
            "attackers": {ip: asdict(e) for ip, e in self.attackers.items()},
        }
