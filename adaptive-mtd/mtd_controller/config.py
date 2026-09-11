"""Config loader for the MTD controller.

Reads /etc/mtd/config.json (path overridable via MTD_CONFIG_PATH env var).
The Ansible role writes this file at provision time; the controller reads it
on startup and re-reads it when the dashboard toggles `mtd_enabled`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


DEFAULT_CONFIG_PATH = Path(os.environ.get("MTD_CONFIG_PATH", "/etc/mtd/config.json"))


@dataclass
class Config:
    # Pools
    vip_pool: List[str] = field(default_factory=list)
    ssh_port_pool: List[int] = field(default_factory=list)
    https_port_pool: List[int] = field(default_factory=list)

    # Adaptive policy
    t_base: int = 60
    decay: float = 0.9
    bump_honeypot: int = 2
    bump_ids_low: int = 1
    bump_ids_med: int = 1
    bump_ids_high: int = 3
    bump_wazuh: int = 1
    threat_cap: int = 10
    tick_seconds: int = 1

    # Topology
    server_ip: str = "172.16.10.10"
    honeypot_ip: str = "172.16.10.20"
    wan_iface: str = "ens33"
    dmz_iface: str = "ens37"

    # Paths
    state_path: str = "/var/log/mtd/state.json"
    rotation_log: str = "/var/log/mtd/rotations.json"
    timeline_log: str = "/var/log/mtd/timeline.json"
    suricata_eve: str = "/var/log/suricata/eve.json"
    cowrie_log: str = "/var/log/cowrie/cowrie.json"

    # Runtime state (also persisted to config so the toggle survives restarts)
    mtd_enabled: bool = False
    current_vip: str = "172.16.10.10"
    current_ssh_port: int = 22
    current_https_port: int = 443

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> "Config":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            vip_pool=list(data.get("vip_pool", [])),
            ssh_port_pool=list(data.get("ssh_port_pool", [])),
            https_port_pool=list(data.get("https_port_pool", [])),
            t_base=int(data.get("t_base", 60)),
            decay=float(data.get("decay", 0.9)),
            bump_honeypot=int(data.get("bump_honeypot", 2)),
            bump_ids_low=int(data.get("bump_ids_low", 1)),
            bump_ids_med=int(data.get("bump_ids_med", 1)),
            bump_ids_high=int(data.get("bump_ids_high", 3)),
            bump_wazuh=int(data.get("bump_wazuh", 1)),
            threat_cap=int(data.get("threat_cap", 10)),
            tick_seconds=int(data.get("tick_seconds", 1)),
            server_ip=data.get("server_ip", "172.16.10.10"),
            honeypot_ip=data.get("honeypot_ip", "172.16.10.20"),
            wan_iface=data.get("wan_iface", "ens33"),
            dmz_iface=data.get("dmz_iface", "ens37"),
            state_path=data.get("state_path", "/var/log/mtd/state.json"),
            rotation_log=data.get("rotation_log", "/var/log/mtd/rotations.json"),
            timeline_log=data.get("timeline_log", "/var/log/mtd/timeline.json"),
            suricata_eve=data.get("suricata_eve", "/var/log/suricata/eve.json"),
            cowrie_log=data.get("cowrie_log", "/var/log/cowrie/cowrie.json"),
            mtd_enabled=bool(data.get("mtd_enabled", False)),
            current_vip=data.get("current_vip", "172.16.10.10"),
            current_ssh_port=int(data.get("current_ssh_port", 22)),
            current_https_port=int(data.get("current_https_port", 443)),
        )

    def save(self, path: Path = DEFAULT_CONFIG_PATH) -> None:
        """Persist the mutable runtime fields back to config.json.

        Only the toggle + current surface are written; the static pools/policy
        are left as Ansible provisioned them. This is what the dashboard calls
        when you flip `mtd_enabled`.
        """
        data = {
            "vip_pool": self.vip_pool,
            "ssh_port_pool": self.ssh_port_pool,
            "https_port_pool": self.https_port_pool,
            "t_base": self.t_base,
            "decay": self.decay,
            "bump_honeypot": self.bump_honeypot,
            "bump_ids_low": self.bump_ids_low,
            "bump_ids_med": self.bump_ids_med,
            "bump_ids_high": self.bump_ids_high,
            "bump_wazuh": self.bump_wazuh,
            "threat_cap": self.threat_cap,
            "tick_seconds": self.tick_seconds,
            "server_ip": self.server_ip,
            "honeypot_ip": self.honeypot_ip,
            "wan_iface": self.wan_iface,
            "dmz_iface": self.dmz_iface,
            "state_path": self.state_path,
            "rotation_log": self.rotation_log,
            "timeline_log": self.timeline_log,
            "suricata_eve": self.suricata_eve,
            "cowrie_log": self.cowrie_log,
            "mtd_enabled": self.mtd_enabled,
            "current_vip": self.current_vip,
            "current_ssh_port": self.current_ssh_port,
            "current_https_port": self.current_https_port,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
