# Demo Script — A/B "with vs without MTD"

A timed, screen-by-screen demo flow. Total runtime ~10 minutes.

## Pre-demo setup (5 min before audience)

1. Boot all 4 VMs.
2. On the **sensor's XFCE desktop** (start it with `startx` if booted to text console), open two windows:
   - Firefox → `https://localhost:43123` — the MTD dashboard
   - A terminal — for the legit client loop
3. On the **attacker VM** (Kali, GUI), open a terminal — for the attack script.
4. Verify the dashboard shows: `mtd_enabled = OFF`, current VIP `172.16.10.10`, current HTTPS port `443`, threat_level `0`, T_eff `60s`.
5. Revert the attacker VM to its `clean-recon` snapshot (so no saved scan data from a previous run).

The demo is fully self-contained — two VMware console windows visible to the audience (sensor + attacker), nothing on the Windows host.

## Legit client loop (run on the sensor's terminal the whole demo)

```bash
bash /opt/mtd-client/follow-surface.sh
```

This loop "follows the surface" — it asks the dashboard for the current public port, then hits it. It stays green the whole demo, even during Run B when the surface is rotating. That's the punchline: legit users follow the service, attackers chase a snapshot.

---

## Run A — MTD OFF (the failure case) — ~3 min

### Screen 1: Dashboard (Tab 3)
- Show `mtd_enabled = OFF` toggle.
- Show frozen surface: VIP `172.16.10.10`, HTTPS port `443`, SSH port `22`.
- threat_level `0`, T_eff `60s` (irrelevant — MTD is off).
- **Narration**: "This is a normal static network. One public IP, one public port per service. Standard."

### Screen 2: Attacker (Tab 2)
Run the full attack:
```bash
python3 /opt/mtd-attacker/run_attack.py --phase all
```
- Phase 1 (scan): nmap finds port 443 + port 22 on `203.0.113.2`. Output: `T1046 scan complete: 2 ports open`.
- Phase 2 (brute): hydra hits port 22 with a small wordlist. Output: `T1110 brute force: credentials found`.
- Phase 3 (web): sqlmap hits `https://203.0.113.2:443/`. Output: `T1190 web exploit: 5 parameters injectable`.
- Phase 4 (ssh): ssh logs in with the brute-forced creds. Output: `T1078 ssh login: success`.
- **Narration**: "Static surface. One scan, full compromise. This is what we fix."

### Screen 3: Client loop (Tab 4)
- Show the green stream of `200 OK` responses.
- **Narration**: "The legit user is fine. So is the attacker. Everyone's happy — except the defender."

### Screen 4: Dashboard (Tab 3)
- Show the rotation log is empty (no rotations — MTD is off).
- threat_level may have ticked up from Suricata alerts, but it doesn't matter — MTD is off.
- **Narration**: "End of Run A. Full compromise in under a minute."

---

## Reset between runs (~1 min)

1. Revert the attacker VM to `clean-recon` snapshot (VMware: VM → Snapshot → revert to `clean-recon`).
2. Wait for it to boot, re-ssh from Windows.
3. On the dashboard, click the **Enable MTD** button.
4. Verify: `mtd_enabled = ON`, threat_level resets to `0`, T_eff `60s`.
5. **Narration**: "Same attacker, same script. Only difference: the surface now moves."

---

## Run B — MTD ON (the defended case) — ~4 min

### Screen 1: Dashboard (Tab 3)
- Show `mtd_enabled = ON`.
- Show the surface is about to rotate — point at T_eff `60s` counting down.
- **Narration**: "MTD is on. Every 60 seconds by default, faster if the network gets noisy."

### Screen 2: Attacker (Tab 2)
Run the same script:
```bash
python3 /opt/mtd-attacker/run_attack.py --phase all
```
- Phase 1 (scan): nmap finds a port — but by the time phase 2 runs, the port has rotated. Output: `T1046 scan complete: 2 ports open` (but stale).
- Phase 2 (brute): hydra hits the old port — connection refused, or lands on the honeypot if the controller redirected. Output: `T1110 brute force: 0 credentials found`.
- Phase 3 (web): sqlmap hits the old port — 404 or connection refused. Output: `T1190 web exploit: 0 parameters injectable`.
- Phase 4 (ssh): ssh hits the old VIP — dropped. Output: `T1078 ssh login: failed`.
- **Narration**: "Same attacker, same script, same tools. Only difference: the surface moves. That's MTD."

### Screen 3: Client loop (Tab 4)
- Show the green stream is still going — never broke.
- **Narration**: "The legit user never noticed. The attacker's map keeps expiring."

### Screen 4: Dashboard (Tab 3)
- Show the rotation log filling up.
- Show threat_level climbing as Suricata/Cowrie fire, T_eff dropping toward ~5s.
- **Narration**: "The defense breathes with the threat. Quiet = slow. Active attack = fast."

---

## Side-by-side comparison (~2 min)

On the dashboard, scroll to the A/B comparison table (rendered after both runs):

| Metric (same attack script) | Run A — MTD OFF | Run B — MTD ON |
|---|---|---|
| Successful port scans | 1 | 1 (but stale) |
| Brute-force attempts hitting real server | high | 0 (honeypot/dead) |
| Web exploit requests reaching the app | high | ~0 |
| SSH sessions on real server | 1+ | 0 |
| Times attacker had to re-scan | 0 | many |
| Service uptime seen by legit client | 100% | 100% |

**Closing narration**: "Same attacker, same script, same tools. Only difference: the surface moves. Legit users follow the service. Attackers chase a snapshot. That's Moving Target Defense."

---

## Timing summary

| Segment | Duration |
|---|---|
| Pre-demo setup | 5 min (before audience) |
| Run A (MTD off) | 3 min |
| Reset | 1 min |
| Run B (MTD on) | 4 min |
| Comparison + close | 2 min |
| **Total** | **~10 min** |

## Troubleshooting the demo

| Symptom | Fix |
|---|---|
| Dashboard not loading | `sudo systemctl status mtd-dashboard` on the sensor; check uvicorn on 43123 |
| Rotations not happening | Check `mtd_enabled` is ON; check `mtd-controller.service` is running |
| Attacker can't reach the sensor | Cloudflare WARP on the host? Disable it. Check `iptables -L -t nat` on the sensor for DNAT rules |
| Client loop breaks | The dashboard API is returning the wrong port? Check `/api/surface` manually with curl |
| Suricata not alerting | `sudo systemctl status suricata`; check `/var/log/suricata/eve.json` is growing |
| Cowrie not logging | `sudo systemctl status cowrie` on the honeypot; check rsyslog on both ends |
