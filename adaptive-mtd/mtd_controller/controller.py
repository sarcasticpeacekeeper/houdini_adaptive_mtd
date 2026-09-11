"""Main controller loop.

Wires together: suricata_reader + cowrie_reader -> policy -> rotator -> state.
Runs forever (one tick per tick_seconds). On each tick:
    1. Drain any pending events from the readers into the policy.
    2. policy.tick() — decay threat_level, recompute T_eff.
    3. If policy.should_rotate() — pick next surface, apply via iptables
       (rewriting both the general DNAT rule AND any per-source attacker
       redirects), record the rotation.
    4. For any newly-flagged attacker source IPs, install per-source
       redirect rules to the honeypot (sticky for the demo).
    5. Persist state.json (so the dashboard can read it).

NEW (redesign): high-severity Suricata events flag the source IP as an
attacker. The controller then installs an iptables rule that DNATs that
source's HTTPS/SSH traffic to the honeypot, while legit traffic keeps
going to the real server. The redirect is sticky for the rest of the demo.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path
from queue import Queue, Empty

from .config import Config, DEFAULT_CONFIG_PATH
from .state import SurfaceState, RotationEvent
from .policy import Policy, Event
from .rotator import Rotator, Rotation
from . import suricata_reader, cowrie_reader


EVENT_TIMEOUT = 0.2


class Controller:
    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.cfg = Config.load(config_path)
        self.policy = Policy(self.cfg)
        self.rotator = Rotator(self.cfg)
        self.state = SurfaceState(
            current_vip=self.cfg.current_vip,
            current_ssh_port=self.cfg.current_ssh_port,
            current_https_port=self.cfg.current_https_port,
            mtd_enabled=self.cfg.mtd_enabled,
        )
        self.state_path = Path(self.cfg.state_path)
        self.rotation_log = Path(self.cfg.rotation_log)
        self.event_queue: Queue = Queue()
        self._stop = threading.Event()
        self._reader_threads = []
        # NEW: track which attackers we've already installed a redirect rule for
        self._installed_redirects: set = set()

    def start_readers(self) -> None:
        for name, reader, path in [
            ("suricata", suricata_reader, self.cfg.suricata_eve),
            ("cowrie", cowrie_reader, self.cfg.cowrie_log),
        ]:
            t = threading.Thread(target=self._reader_loop, args=(name, reader, path), daemon=True)
            t.start()
            self._reader_threads.append(t)

    def _reader_loop(self, name, reader, path) -> None:
        try:
            for event in reader.tail_events(path):
                if self._stop.is_set():
                    return
                self.event_queue.put(event)
        except Exception as e:
            print(f"[controller] {name} reader crashed: {e}", file=sys.stderr)

    def drain_events(self) -> int:
        """Pull all pending events from the queue into the policy.
        Returns count of events processed."""
        count = 0
        while True:
            try:
                event = self.event_queue.get(timeout=EVENT_TIMEOUT)
            except Empty:
                break
            self.policy.apply_event(event)
            count += 1
        return count

    def install_new_attacker_redirects(self) -> None:
        """For any attacker the policy has flagged but we haven't installed
        a redirect rule for yet, install one now. Sticky for the demo."""
        for src_ip in self.policy.attackers:
            if src_ip in self._installed_redirects:
                continue
            self.rotator.add_attacker_redirect(
                src_ip=src_ip,
                current_https_port=self.state.current_https_port,
                current_ssh_port=self.state.current_ssh_port,
            )
            self._installed_redirects.add(src_ip)
            # Record in state for the dashboard
            log = self.policy.attacker_log[-1] if self.policy.attacker_log else None
            if log:
                self.state.add_attacker(
                    src_ip=src_ip,
                    sid=log.get("sid", 0),
                    message=log.get("message", "suricata high-severity alert"),
                    honeypot_ip=self.cfg.honeypot_ip,
                )
            print(f"[controller] attacker flagged: {src_ip} -> honeypot "
                   f"{self.cfg.honeypot_ip}", file=sys.stderr)

    def maybe_rotate(self) -> bool:
        """Rotate if policy says so. On rotation, rewrite BOTH the general
        DNAT rule AND all per-source attacker redirects to the new port."""
        now = time.time()
        if not self.policy.should_rotate(now):
            return False
        new_vip, new_ssh, new_https = self.rotator.pick_next(
            self.state.current_vip, self.state.current_ssh_port, self.state.current_https_port
        )
        rotation = Rotation(
            new_vip=new_vip, new_ssh_port=new_ssh, new_https_port=new_https,
            old_vip=self.state.current_vip,
            old_ssh_port=self.state.current_ssh_port,
            old_https_port=self.state.current_https_port,
            reason="scheduled" if (now - self.policy.last_rotation) >= self.policy.t_eff else self.policy.last_event_reason,
        )
        # Apply rotation, passing all currently-flagged attacker IPs so
        # their per-source redirects get rewritten to the new public port.
        self.rotator.apply(rotation, attacker_ips=list(self.policy.attackers))
        self.state.current_vip = new_vip
        self.state.current_ssh_port = new_ssh
        self.state.current_https_port = new_https
        event_record = RotationEvent(
            timestamp=now,
            old_vip=rotation.old_vip, new_vip=new_vip,
            old_ssh_port=rotation.old_ssh_port, new_ssh_port=new_ssh,
            old_https_port=rotation.old_https_port, new_https_port=new_https,
            threat_level=self.policy.threat_level,
            t_eff=self.policy.t_eff,
            reason=rotation.reason,
        )
        self.state.record_rotation(event_record, self.rotation_log)
        self.policy.mark_rotated(now)
        self.cfg.current_vip = new_vip
        self.cfg.current_ssh_port = new_ssh
        self.cfg.current_https_port = new_https
        self.cfg.save(self.config_path)
        return True

    def sync_runtime_state(self) -> None:
        self.state.threat_level = self.policy.threat_level
        self.state.t_eff = self.policy.t_eff
        self.state.mtd_enabled = self.cfg.mtd_enabled

    def persist_state(self) -> None:
        self.sync_runtime_state()
        self.state.save(self.state_path)

    def reload_config(self) -> None:
        self.cfg = Config.load(self.config_path)
        self.policy.cfg = self.cfg

    def run(self) -> None:
        print(f"[controller] starting. mtd_enabled={self.cfg.mtd_enabled} "
              f"vip={self.cfg.current_vip} ssh={self.cfg.current_ssh_port} "
              f"https={self.cfg.current_https_port}", file=sys.stderr)
        self.start_readers()
        last_persist = 0.0
        while not self._stop.is_set():
            self.reload_config()
            self.drain_events()
            self.policy.tick()
            self.install_new_attacker_redirects()
            self.maybe_rotate()
            now = time.time()
            if now - last_persist >= 1.0:
                self.persist_state()
                last_persist = now
            time.sleep(self.cfg.tick_seconds)
        self.persist_state()
        print("[controller] stopped", file=sys.stderr)

    def stop(self, *_args) -> None:
        self._stop.set()


def main() -> None:
    ctrl = Controller()
    signal.signal(signal.SIGTERM, ctrl.stop)
    signal.signal(signal.SIGINT, ctrl.stop)
    ctrl.run()


if __name__ == "__main__":
    main()
