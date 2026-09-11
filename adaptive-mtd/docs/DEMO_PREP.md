# Demo Preparation Guide

## Before the audience arrives

### 1. Boot all 5 VMs
- Sensor (VM-2) — Ubuntu 24.04 + XFCE
- Server (VM-3) — Ubuntu 24.04 Server
- Honeypot (VM-4) — Ubuntu 24.04 Server
- Attacker (VM-1) — Kali 2026
- Client (VM-6, optional) — Ubuntu 24.04 Server on WAN

### 2. On the sensor (XFCE desktop)
Open two windows:
- **Firefox** → `http://localhost:43123` (the dashboard)
- **Terminal** → `bash /opt/mtd-client/follow-surface.sh` (the green client loop)

Verify the dashboard shows:
- `MTD Status: OFF`
- `Threat Level: 0`
- `T_rot: 60 s`
- `Current VIP: 172.16.10.10`
- `Redirected Attackers`: (empty)
- `Recent Rotations`: (empty)

The client loop should show green `200` lines every 2s.

### 3. On the attacker (Kali)
Open a terminal. Revert to `clean-recon` snapshot if not already clean.

### 4. On the client VM (if using)
Open a terminal → `bash /opt/mtd-client/follow-surface.sh`

Should show green `200` lines (benign user reaching the server through the public surface).

---

## The demo flow (~10 min)

### Phase 0 — Benign access (MTD off)
**Narration**: "First, a normal request. The attacker reaches the service, sees the real page. Everything works."

```bash
# on the attacker
curl -k https://203.0.113.2:443/ | grep 'v2.1.4'
```
**Expected**: `v2.1.4 - server`

### Phase 1 — nmap scan (MTD off, no redirect)
**Narration**: "The attacker scans. Suricata sees it, bumps the threat level, speeds up rotation — but the scan alone doesn't redirect. The attacker is still on the real server."

```bash
# on the attacker
nmap -n -sS -p 1-100 --open -Pn 203.0.113.2
```
**Check dashboard**: `Threat Level > 0`, `T_rot < 60`, **Redirected Attackers**: empty.

### Phase 2 — hydra brute force (triggers redirect)
**Narration**: "Now the attacker brute-forces SSH. Suricata fires a high-severity alert. The controller flags the source IP and redirects them to the honeypot. From this moment on, every request from the attacker goes to the decoy."

```bash
# on the attacker
hydra -L /opt/mtd-attacker/users.txt -P /opt/mtd-attacker/pass.txt -s 22 -f -t 16 ssh://203.0.113.2
```
**Check dashboard**: **Redirected Attackers** panel shows `203.0.113.50`.

### Phase 3 — Same curl, now redirected
**Narration**: "Same request, same page — but the label changed from 'server' to 'honeypot'. The attacker thinks they're still on the real server. They're on a decoy. The real server never saw this request."

```bash
# on the attacker
curl -k https://203.0.113.2:443/ | grep 'v2.1.4'
```
**Expected**: `v2.1.4 - honeypot`

### Phase 4 — Prove it with the access logs
**Narration**: "The server's log shows the benign request. The honeypot's log shows the attacker's post-brute-force request. Same page, different backend — the redirect worked."

```bash
# on the sensor — server's log
sudo tail -3 /var/log/nginx/mtd-access.log
# on the honeypot — honeypot's log
sudo tail -3 /var/log/nginx/dummy-access.log
```
**Expected**:
- Server's log: shows the benign curl (Phase 0), not the post-brute-force one
- Honeypot's log: shows the post-brute-force curl

### Phase 5 — Enable MTD + re-scan (surface rotates)
**Narration**: "Now we enable MTD. The surface starts rotating. The attacker's recon is stale — the port they scanned is dark. And they're still on the honeypot. Legit users follow the service; attackers chase a snapshot."

On the dashboard, click **Enable MTD**. Wait for a rotation (Recent Rotations table populates), then:
```bash
# on the attacker
nmap -n -sS -p 1-100 --open -Pn 203.0.113.2
```
**Expected**: old port is dark (surface rotated), attacker still on honeypot.

### Closing
**Narration**: "Same attacker, same script, same tools. Only difference: the surface moves, and detected attackers go to a decoy. Legit users follow the service. Attackers chase a snapshot. That's Moving Target Defense."

---

## Cross questions (likely from reviewers)

### Q: Does MTD break established sessions?
**A**: No. MTD only blocks **new** connections to the old surface. Established sessions continue through conntrack. This is a known MTD limitation — session management is out of scope (would require conntrack flush, which breaks legit users too).

### Q: Can the attacker tell they're on the honeypot?
**A**: Not by the page content — both serve the identical "Internal Portal - Login" page. The only difference is the footer label (`server` vs `honeypot`) and the IP/port (which rotates). The attacker can't tell only by checking the label, which the audience sees but the attacker doesn't (they've already been redirected).

### Q: What if the attacker re-scans?
**A**: The new scan finds the **current** public port (the surface rotated). But the attacker is still flagged (sticky redirect) — their new connections still go to the honeypot. Re-scanning doesn't help because the per-source redirect persists.

### Q: How does the benign user stay connected during rotation?
**A**: The client loop polls the dashboard API for the current port every 2s, then hits it. When the surface rotates, the next poll gets the new port — the legit user follows the surface. The attacker doesn't (they use the stale port from their scan).

### Q: What triggers the redirect?
**A**: A **high-severity (severity 1) Suricata alert** with a source IP. The brute-force rule (SID 9000002) is severity 1. The port-scan rule (SID 9000001) is severity 2 (medium) — it bumps threat_level (faster rotation) but doesn't redirect. Only active attack (brute force, web exploit) triggers the redirect.

### Q: Why is the controller on the sensor, not the server?
**A**: If the server falls, the defender doesn't. The brain (controller) must survive the defended asset. Also, Suricata and iptables run on the sensor — the controller reads EVE JSON and updates NAT rules locally (no network hop).

### Q: What's the adaptive part?
**A**: `T_rot = T_base / (1 + threat_level)`. Quiet → 60s, active attack → ~5s. The rotation rate scales with the threat, not a fixed high cost.
