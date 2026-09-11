"""Surface rotator — applies iptables DNAT changes to rotate the public
VIP/port, and installs per-source redirects for flagged attackers.

Two layers of iptables NAT in PREROUTING (top-to-bottom, first match wins):

    1. (top)    per-source attacker rules: -s <attacker_ip> -> honeypot:443
    2. (below)  general rotation rule:  -> <current_server_vip>:443

So traffic from a flagged attacker hits rule 1 first and goes to the
honeypot's dummy website. Traffic from anyone else falls through to rule 2
and goes to the real server (rotating VIP).

On rotation, the rotator rewrites BOTH the general rule AND every
per-source attacker rule to use the new public port (so the attacker's
redirect stays valid after the surface rotates).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Iterable, Tuple


@dataclass
class Rotation:
    new_vip: str
    new_ssh_port: int
    new_https_port: int
    old_vip: str
    old_ssh_port: int
    old_https_port: int
    reason: str


class Rotator:
    """Picks the next surface, applies it via iptables, and manages
    per-source attacker redirects to the honeypot."""

    def __init__(self, config):
        self.cfg = config

    def pick_next(self, current_vip: str, current_ssh: int, current_https: int) -> Tuple[str, int, int]:
        """Round-robin to the next VIP/port in each pool. Always different from current."""
        vip_pool = self.cfg.vip_pool or [current_vip]
        ssh_pool = self.cfg.ssh_port_pool or [current_ssh]
        https_pool = self.cfg.https_port_pool or [current_https]

        try:
            i = vip_pool.index(current_vip)
        except ValueError:
            i = -1
        new_vip = vip_pool[(i + 1) % len(vip_pool)]

        try:
            j = ssh_pool.index(current_ssh)
        except ValueError:
            j = -1
        new_ssh = ssh_pool[(j + 1) % len(ssh_pool)]

        try:
            k = https_pool.index(current_https)
        except ValueError:
            k = -1
        new_https = https_pool[(k + 1) % len(https_pool)]

        if new_vip == current_vip and new_ssh == current_ssh and new_https == current_https:
            if len(vip_pool) > 1:
                new_vip = vip_pool[(i + 2) % len(vip_pool)]
            elif len(ssh_pool) > 1:
                new_ssh = ssh_pool[(j + 2) % len(ssh_pool)]
            elif len(https_pool) > 1:
                new_https = https_pool[(k + 2) % len(https_pool)]

        return new_vip, new_ssh, new_https

    def apply(self, rotation: Rotation, attacker_ips: Iterable[str] = ()) -> None:
        """Swap the iptables DNAT rules. Also rewrite per-source attacker
        redirects to use the new public port.

        Best-effort: logs errors to stderr but doesn't raise.
        """
        attacker_ips = list(attacker_ips)
        iface = self.cfg.wan_iface
        honeypot = self.cfg.honeypot_ip

        # --- HTTPS ---
        # 1. Remove all existing HTTPS DNAT rules (general + per-source)
        self._clear_dnat(iface, rotation.old_https_port)
        # 2. Re-add per-source attacker rules (highest priority, top of chain)
        for ip in attacker_ips:
            self._insert_dnat(iface, src=ip, port=rotation.new_https_port,
                               target=f"{honeypot}:443")
        # 3. Append the general rotation rule (lowest priority, catches everyone else)
        self._append_dnat(iface, port=rotation.new_https_port,
                          target=f"{rotation.new_vip}:443")

        # --- SSH ---
        self._clear_dnat(iface, rotation.old_ssh_port)
        for ip in attacker_ips:
            self._insert_dnat(iface, src=ip, port=rotation.new_ssh_port,
                               target=f"{honeypot}:22")
        self._append_dnat(iface, port=rotation.new_ssh_port,
                         target=f"{rotation.new_vip}:22")

    def add_attacker_redirect(self, src_ip: str, current_https_port: int,
                              current_ssh_port: int) -> None:
        """Insert per-source redirect rules for a newly-flagged attacker.
        Inserted at the top of PREROUTING so they win over the general rule.
        Called by the controller when the policy flags a new attacker.
        """
        iface = self.cfg.wan_iface
        honeypot = self.cfg.honeypot_ip
        self._insert_dnat(iface, src=src_ip, port=current_https_port,
                          target=f"{honeypot}:443")
        self._insert_dnat(iface, src=src_ip, port=current_ssh_port,
                          target=f"{honeypot}:22")

    # --- low-level iptables helpers ---

    def _insert_dnat(self, iface: str, port: int, target: str, src: str = None) -> None:
        """Insert a DNAT rule at the top of PREROUTING (priority for attackers)."""
        cmd = ["iptables", "-t", "nat", "-I", "PREROUTING", "1",
               "-i", iface, "-p", "tcp", "--dport", str(port)]
        if src:
            cmd += ["-s", src]
        cmd += ["-j", "DNAT", "--to-destination", target]
        self._run(cmd)

    def _append_dnat(self, iface: str, port: int, target: str) -> None:
        """Append a DNAT rule at the bottom of PREROUTING (general rotation)."""
        cmd = ["iptables", "-t", "nat", "-A", "PREROUTING",
               "-i", iface, "-p", "tcp", "--dport", str(port),
               "-j", "DNAT", "--to-destination", target]
        self._run(cmd)

    def _clear_dnat(self, iface: str, port: int) -> None:
        """Delete all DNAT rules on the given interface + port (general + per-source).
        Repeats until none remain (handles multiple per-source rules).
        """
        while True:
            # Delete any matching rule (no -s = match all sources)
            cmd = ["iptables", "-t", "nat", "-D", "PREROUTING",
                   "-i", iface, "-p", "tcp", "--dport", str(port),
                   "-j", "DNAT"]
            rc, _, _ = self._run(cmd, check=False)
            if rc != 0:
                break  # no more matching rules

    @staticmethod
    def _run(cmd: list, check: bool = True) -> tuple:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
            if check and r.returncode != 0:
                import sys
                print(f"[rotator] cmd failed: {' '.join(cmd)}\nstderr: {r.stderr}",
                      file=sys.stderr)
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return 127, "", "iptables not found"
