"""Adaptive policy — the threat_level state machine + attacker flagging.

Inputs: events from suricata_reader and cowrie_reader (and a stubbed wazuh_reader).
Outputs:
    - threat_level (0..10) -> controls T_eff (rotation period)
    - attacker_set (source IPs flagged as attackers) -> drives per-source
      redirection to the honeypot's dummy website

The controller calls policy.tick() every tick_seconds; policy.apply_event()
is called whenever a reader emits a normalized event.

NEW (redesign): a high-severity Suricata event flags the source IP as an
attacker. Once flagged, the controller redirects that source's HTTPS
traffic to the honeypot. Sticky for the rest of the demo (no cooldown).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional, Set


@dataclass
class Event:
    """Normalized event from any reader."""
    source: str        # "suricata" | "cowrie" | "wazuh"
    severity: str      # "low" | "medium" | "high"
    message: str       # human-readable
    src_ip: Optional[str] = None  # source IP of the attacker (NEW)
    sid: Optional[int] = None      # Suricata SID
    eventid: Optional[str] = None  # Cowrie eventid
    timestamp: float = 0.0


class Policy:
    """Threat_level state machine + attacker flagging.

    threat_level is a float in [0, threat_cap].
    - apply_event bumps it up based on the event source/severity.
    - tick decays it (threat_level *= decay) and recomputes T_eff.
    - should_rotate returns True when time since last rotation >= T_eff.

    NEW: apply_event also flags the source IP as an attacker when the
    event is a high-severity Suricata alert. The controller reads the
    attacker set and installs per-source iptables redirects to the honeypot.
    """

    def __init__(self, config):
        self.cfg = config
        self.threat_level: float = 0.0
        self.last_rotation: float = time.time()
        self.t_eff: float = float(config.t_base)
        self.last_event_reason: str = "scheduled"
        # NEW: set of source IPs flagged as attackers
        self.attackers: Set[str] = set()
        # NEW: log of flagging events (src_ip, sid, message, timestamp)
        self.attacker_log: list = []

    def apply_event(self, event: Event) -> None:
        """Bump threat_level based on the event. Cap at threat_cap.
        Also flag the source IP as an attacker on a high-severity Suricata alert."""
        bump = self._bump_for(event)
        if bump > 0:
            self.threat_level = min(self.threat_level + bump, self.cfg.threat_cap)
            self.last_event_reason = event.message
            self._recompute_t_eff()
        # NEW: flag attacker on high-severity Suricata event with a src_ip
        if (event.source == "suricata"
                and event.severity == "high"
                and event.src_ip
                and event.src_ip not in self.attackers):
            self.attackers.add(event.src_ip)
            self.attacker_log.append({
                "src_ip": event.src_ip,
                "sid": event.sid,
                "message": event.message,
                "timestamp": time.time(),
            })

    def _bump_for(self, event: Event) -> int:
        if event.source == "cowrie":
            return self.cfg.bump_honeypot
        if event.source == "suricata":
            if event.severity == "high":
                return self.cfg.bump_ids_high
            if event.severity == "medium":
                return self.cfg.bump_ids_med
            return self.cfg.bump_ids_low
        if event.source == "wazuh":
            return self.cfg.bump_wazuh
        return 0

    def tick(self) -> None:
        """Called every tick_seconds. Decays threat_level and recomputes T_eff."""
        self.threat_level *= self.cfg.decay
        if self.threat_level < 0.01:
            self.threat_level = 0.0
        self._recompute_t_eff()

    def _recompute_t_eff(self) -> None:
        self.t_eff = self.cfg.t_base / (1.0 + self.threat_level)

    def should_rotate(self, now: float) -> bool:
        """True when MTD is enabled and time since last rotation >= T_eff."""
        if not self.cfg.mtd_enabled:
            return False
        return (now - self.last_rotation) >= self.t_eff

    def mark_rotated(self, now: float) -> None:
        self.last_rotation = now

    def is_attacker(self, src_ip: str) -> bool:
        return src_ip in self.attackers

    def to_dict(self) -> dict:
        return {
            "threat_level": round(self.threat_level, 2),
            "t_eff": round(self.t_eff, 2),
            "last_event_reason": self.last_event_reason,
            "attackers": list(self.attackers),
            "attacker_log": self.attacker_log[-20:],
        }
