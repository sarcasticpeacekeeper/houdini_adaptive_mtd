# Sensor VM — Complete Setup & Configuration Reference

This document explains every component on the Sensor VM (VM-2) so you can answer any cross question about it.

## 1. Network Configuration

### Netplan — `/etc/netplan/01-mtd.yaml`

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:                          # WAN — faces the attacker (VMnet2)
      addresses: [203.0.113.2/24]
      routes:
        - to: default
          via: 203.0.113.1       # Windows host adapter (placeholder upstream, egress dropped)
    ens37:                          # LAN — reserved for future Client VM (VMnet4)
      addresses: [192.168.10.1/24]
    ens38:                          # DMZ — faces the server + honeypot (VMnet3)
      addresses: [172.16.10.1/24]
```

**Why 3 NICs:**
- `ens33` (WAN, 203.0.113.0/24) — the attacker's segment. The sensor's WAN IP is `203.0.113.2`. The default route goes to `203.0.113.1` (the Windows host on VMnet2), but egress is dropped in iptables (the "internet" is simulated, no real upstream).
- `ens37` (LAN, 192.168.10.0/24) — reserved for the future Client VM. The sensor is the gateway (`192.168.10.1`).
- `ens38` (DMZ, 172.16.10.0/24) — the server and honeypot segment. The sensor is the gateway (`172.16.10.1`).

**Note:** The NIC names `ens37` and `ens38` were swapped during setup (VMware assigned them in a different order than expected). The DMZ is `ens38`, the LAN is `ens37`. This is documented in the config and iptables rules.

### IP Forwarding

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-mtd.conf
sudo sysctl --system
```

The sensor routes between segments (WAN→DMZ, DMZ→WAN). Without this, the DNAT and FORWARD rules won't work.

### NetworkManager

NetworkManager was **disabled** because it regenerates netplan files (`90-NM-*.yaml`) that override our config, causing IPs to drop on reboot. The fix:

```bash
sudo systemctl disable --now NetworkManager
sudo mv /etc/netplan/01-network-manager-all.yaml /etc/netplan.bak/
sudo mv /etc/netplan/50-cloud-init.yaml /etc/netplan.bak/
sudo mv /etc/netplan/90-NM-*.yaml /etc/netplan.bak/
```

Only `/etc/netplan/01-mtd.yaml` remains. IPs survive reboot.

## 2. iptables — `/etc/iptables/rules.v4`

The sensor's firewall + NAT. Loaded by `netfilter-persistent` on boot.

### Filter table (INPUT)

```
:INPUT DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i ens33 -p tcp --dport 22 -s 203.0.113.0/24 -j ACCEPT    # SSH to sensor
-A INPUT -p icmp -j ACCEPT
-A INPUT -i ens38 -p tcp --dport 514 -s 172.16.10.20/32 -j ACCEPT    # rsyslog from honeypot
```

### Filter table (FORWARD)

```
:FORWARD DROP
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i ens33 -o ens38 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass   # WAN→DMZ → Suricata
-A FORWARD -i ens33 -o ens38 -j ACCEPT    # WAN→DMZ (allow after Suricata)
-A FORWARD -i ens38 -o ens33 -j ACCEPT    # DMZ→WAN
```

**NFQUEUE:** WAN→DMZ new connections go to Suricata (inline IPS) via NFQ queue 0. `--queue-bypass` lets packets through if Suricata is slow.

### Nat table (PREROUTING)

```
:PREROUTING ACCEPT
-A POSTROUTING -o ens33 -s 172.16.10.0/24 -j MASQUERADE           # DMZ→WAN SNAT
-A PREROUTING -i ens33 -p tcp --dport 443 -j DNAT --to-destination 172.16.10.10:443   # HTTPS → server
-A PREROUTING -i ens33 -p tcp --dport 22 -j DNAT --to-destination 172.16.10.10:22     # SSH → server
```

**DNAT:** The public surface. Port 443 (HTTPS) and 22 (SSH) on the WAN IP are DNATed to the server's internal ports. The MTD controller rewrites these rules to rotate the VIP/port.

**Per-source redirect (attacker → honeypot):** When the controller flags an attacker, it inserts rules at the TOP of PREROUTING (highest priority):

```
iptables -t nat -I PREROUTING 1 -i ens33 -s 203.0.113.50 -p tcp --dport 443 -j DNAT --to 172.16.10.20:443
iptables -t nat -I PREROUTING 1 -i ens33 -s 203.0.113.50 -p tcp --dport 22 -j DNAT --to 172.16.10.20:22
```

These rules send the attacker's traffic to the honeypot (`172.16.10.20`). First match wins (per-source rules are above the general rules). On rotation, the controller rewrites both the general rules AND the per-source rules to use the new public port.

## 3. Suricata — inline IPS (NFQ mode)

### Service

```bash
sudo systemctl status suricata
# ExecStart: /usr/bin/suricata -q 0 -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
```

**`-q 0`** = NFQ mode (inline IPS), reading from NFQUEUE queue 0.

### systemd override — `/etc/systemd/system/suricata.service.d/override.conf`

```ini
[Service]
Type=simple
ExecStart=
ExecStart=/usr/bin/suricata -q 0 -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
```

**Why `Type=simple`:** Suricata with `-q 0` runs in the foreground. `Type=forking` (the default) expects a fork signal that never comes → timeout. `Type=simple` lets systemd track the process directly.

**Why no `-D`:** The `-D` (debug) flag disables logging ("no logging compatible with daemon mode") → eve.json stays empty. Removed.

### Config — `/etc/suricata/suricata.yaml`

```yaml
nfq:
  mode: accept
  fail-open: yes          # let packets through if Suricata is slow

outputs:
  - eve-log:
      enabled: yes
      filename: eve.json          # /var/log/suricata/eve.json

vars:
  address-groups:
    HOME_NET: "[203.0.113.0/24,172.16.10.0/24,192.168.10.0/24]"
    HTTP_SERVERS: "$HOME_NET"     # required by ET/Open rules
    # ... (all standard *_SERVERS vars: SSH_SERVERS, SMTP_SERVERS, DNS_SERVERS, TELNET_SERVERS, SQL_SERVERS, SIP_SERVERS, RDP_SERVERS, AIM_SERVERS, DC_SERVERS, IRC_SERVERS, DICT_SERVERS, GAME_SERVERS, MSSQL_SERVERS, NTP_SERVERS, TFTP_SERVERS, TNS_SERVERS, FINGER_SERVERS, SMB_SERVERS, SNMP_SERVERS, RLOGIN_SERVERS, RSH_SERVERS, BOSSA_PWD_SERVERS, BOSSA_CHD_SERVERS)
  port-groups:
    HTTP_PORTS: "80,443,8443,4443,8444,4444"
    SSH_PORTS: "22,2222,22022,20222,22002"
    # ... (all standard *_PORTS vars: TELNET_PORTS, RLOGIN_PORTS, RSH_PORTS, RDP_PORTS, DNP3_PORTS, SIP_PORTS, AIM_PORTS, IRC_PORTS, DC_PORTS, MSN_PORTS, MSSQL_PORTS, NTP_PORTS, TFTP_PORTS, TNS_PORTS, FINGER_PORTS, SMB_PORTS, SNMP_PORTS, ORACLE_PORTS, BOSSA_PWD_PORTS, BOSSA_CHD_PORTS, SHELLCODE_PORTS, FILE_DATA_PORTS, GTPU_DATA_PORTS, TFTP_DATA_PORTS)

rule-files:
  - suricata.rules           # ET/Open (populated by suricata-update)
  - /etc/suricata/rules/mtd.rules   # lab custom rules
```

**Why no `af-packet`:** `af-packet` is passive sniffing. NFQ mode reads from the queue. Having both conflicts — Suricata would sniff the interface AND read the queue, causing duplicates/stalls. Removed `af-packet` and `runmode: workers` (which is for af-packet).

**Why all the `*_SERVERS` and `*_PORTS`:** The ET/Open ruleset uses variables like `HTTP_SERVERS`, `SQL_SERVERS`, `ORACLE_PORTS`. Without them, 6680+ ET/Open rules fail to parse → Suricata won't start. The full standard set is defined.

### Custom rules — `/etc/suricata/rules/mtd.rules`

```
# SID 9000001 — T1046 port scan (severity 2 = medium, priority 2)
# SID 9000002 — T1110 SSH brute force (severity 1 = high, priority 1) → triggers redirect
# SID 9000003 — T1190 sqlmap user-agent (severity 1 = high) → triggers redirect
# SID 9000004 — T1190 SQLi probe pattern (severity 1 = high) → triggers redirect
# SID 9000005 — T1592 service version probe (severity 2 = medium, priority 2)
```

**Key rules:**
- `flags:S` — SYN packets
- `detection_filter:track by_src, count N, seconds M` — N SYNs from the source in M seconds
- `content:"..."` — content keyword (must come BEFORE `http_user_agent` / `http_uri` in Suricata 7)
- `priority:1` = severity 1 (high) → triggers attacker redirect
- `priority:2` = severity 2 (medium) → bumps threat_level only

**Why `flow:to_server` was removed from SID 9000002:** The brute-force rule needs to match SYN packets. `flow:to_server` requires an established flow, which SYN packets don't have → the rule wouldn't fire on port scans. Removed so SYN packets match.

## 4. MTD Controller — `/opt/mtd-controller/mtd_controller/`

The brain. Runs as `mtd-controller.service` (systemd, as root for iptables access).

### Modules

| File | Purpose |
|---|---|
| `config.py` | Loads `/etc/mtd/config.json` (pools, timing, toggle, current surface) |
| `state.py` | Current surface (VIP, ports) + rotation history + attackers dict. Written to `/var/log/mtd/state.json` every tick. |
| `policy.py` | Threat level state machine. `apply_event()` bumps `threat_level` and flags attackers (high-severity only). `tick()` decays. `should_rotate()` returns True when `T_rot` expires. |
| `suricata_reader.py` | Tails `/var/log/suricata/eve.json`. Parses alert events. Maps severity (1→high, 2→medium, 3→low). Extracts `src_ip`. |
| `cowrie_reader.py` | Tails `/var/log/cowrie/cowrie.json` (received from honeypot via rsyslog). Parses Cowrie events. |
| `rotator.py` | Applies iptables DNAT changes. `pick_next()` round-robins through the VIP/port pools. `apply()` swaps the general rules AND per-source attacker rules. |
| `controller.py` | Main loop. Wires readers → policy → rotator → state. Runs every `tick_seconds` (1s). |

### Config — `/etc/mtd/config.json`

```json
{
  "vip_pool": ["172.16.10.10","172.16.10.11","172.16.10.12","172.16.10.13","172.16.10.14"],
  "ssh_port_pool": [22, 2222, 22022, 20222, 22002],
  "https_port_pool": [443, 8443, 4443, 8444, 4444],
  "t_base": 60,
  "decay": 0.9,
  "bump_honeypot": 2,
  "bump_ids_high": 3,
  "bump_ids_med": 1,
  "threat_cap": 10,
  "tick_seconds": 1,
  "server_ip": "172.16.10.10",
  "honeypot_ip": "172.16.10.20",
  "wan_iface": "ens33",
  "dmz_iface": "ens38",
  "mtd_enabled": false,
  "current_vip": "172.16.10.10",
  "current_ssh_port": 22,
  "current_https_port": 443
}
```

**Key fields:**
- `mtd_enabled` — the toggle (false = Run A, true = Run B)
- `current_vip` / `current_ssh_port` / `current_https_port` — the current public surface (rotates)
- `vip_pool` / `ssh_port_pool` / `https_port_pool` — the rotation pools
- `t_base` / `decay` / `bump_*` / `threat_cap` — the adaptive policy

### systemd unit — `/etc/systemd/system/mtd-controller.service`

```ini
[Unit]
Description=Adaptive MTD Controller (the brain)
After=network-online.target suricata.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mtd-controller
ExecStart=/opt/mtd-controller/venv/bin/python -m mtd_controller.controller
Restart=on-failure
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

**Runs as root** (needs iptables). The venv at `/opt/mtd-controller/venv/` has `pyyaml`.

### The adaptive policy

```
threat_level: float in [0..10]

apply_event(event):
  - Suricata alert, severity 1 (high) → +3, AND flag src_ip as attacker
  - Suricata alert, severity 2 (medium) → +1 (no flag)
  - Cowrie event → +2 (no flag, honeypot bump only)

tick():
  - threat_level *= decay (0.9 per tick)
  - recompute T_rot = T_base / (1 + threat_level)

should_rotate(now):
  - True when mtd_enabled AND (now - last_rotation) >= T_rot
```

**Quiet → 60s, active attack → ~5s.** The defense breathes with the threat.

### Attacker redirect

When a high-severity Suricata alert fires with a `src_ip`, the controller:
1. `policy.attackers.add(src_ip)` — flags the source IP
2. `state.attackers[src_ip] = {...}` — records in state
3. `rotator.add_attacker_redirect(src_ip, current_ports)` — installs per-source iptables DNAT rules (attacker → honeypot)
4. Sticky for the rest of the demo (no cooldown)

On rotation, the controller rewrites BOTH the general DNAT rules AND all per-source attacker rules to use the new public port.

## 5. Dashboard — `/opt/mtd-dashboard/`

The view. Runs as `mtd-dashboard.service` (FastAPI on port 43123).

### Files

| File | Purpose |
|---|---|
| `main.py` | FastAPI app. Endpoints: `GET /` (HTML), `GET /api/surface`, `GET /api/state`, `GET /api/rotations`, `GET /api/attackers`, `GET /api/alerts`, `POST /api/toggle`, `POST /api/reset`. Reads `state.json` + `eve.json`. |
| `templates/index.html` | Jinja2 template. Shows: current surface, threat level, T_rot, recent alerts, redirected attackers, recent rotations. Auto-refreshes every 3s. |

### Endpoints

| Endpoint | Returns |
|---|---|
| `GET /` | HTML dashboard |
| `GET /api/surface` | JSON: current VIP, ports, threat_level, T_rot, mtd_enabled |
| `GET /api/state` | JSON: full state |
| `GET /api/rotations` | JSON: last 100 rotation events |
| `GET /api/attackers` | JSON: redirected attackers dict |
| `GET /api/alerts` | JSON: last 20 Suricata alerts from eve.json |
| `POST /api/toggle` | Flips `mtd_enabled` in config.json |
| `POST /api/reset` | Runs `/opt/mtd-client/reset.sh` (clears everything) |

### systemd unit — `/etc/systemd/system/mtd-dashboard.service`

```ini
[Unit]
Description=Adaptive MTD Dashboard (FastAPI on port 43123)
After=network-online.target mtd-controller.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mtd-dashboard/dashboard
ExecStart=/opt/mtd-dashboard/venv/bin/uvicorn main:app --host 0.0.0.0 --port 43123
Restart=on-failure
RestartSec=3
Environment=PYTHONUNBUFFERED=1
Environment=MTD_CONFIG_PATH=/etc/mtd/config.json
Environment=MTD_STATE_PATH=/var/log/mtd/state.json
Environment=MTD_ROTATION_LOG=/var/log/mtd/rotations.json

[Install]
WantedBy=multi-user.target
```

**Port 43123** — uncommon port (avoids conflicts). The venv at `/opt/mtd-dashboard/venv/` has `fastapi`, `uvicorn`, `jinja2`, `requests`, `python-multipart`.

## 6. Client Loop — `/opt/mtd-client/follow-surface.sh`

The legit user. Runs on the sensor (or a client VM on the WAN). Polls the dashboard for the current VIP and hits the server's 443 on the DMZ.

```bash
DASHBOARD="http://localhost:43123/api/surface"
while true; do
    vip=$(curl -s "$DASHBOARD" | jq -r '.current_vip // empty')
    curl -k --resolve "svc.local:443:$vip" "https://svc.local:443/" -o /dev/null -s -w "$(date +%T) %{http_code}\n"
    sleep 2
done
```

**Why it stays green:** It polls the dashboard every 2s for the current VIP. When the surface rotates, the next poll gets the new VIP → the legit user follows the surface. The attacker doesn't (they use the stale port from their scan).

## 7. Reset Script — `/opt/mtd-client/reset.sh`

Clears all MTD state for a clean demo run:

```bash
#!/bin/bash
sudo systemctl stop mtd-controller 2>/dev/null
sudo pkill -9 suricata 2>/dev/null
sudo pkill -9 -f 'suricata -q 0' 2>/dev/null
sleep 2
sudo rm -f /run/suricata.pid /var/run/suricata.pid
sudo tee /etc/systemd/system/suricata.service.d/override.conf > /dev/null <<'CFG'
[Service]
Type=simple
ExecStart=
ExecStart=/usr/bin/suricata -q 0 -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
CFG
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 443 -j DNAT --to-destination 172.16.10.10:443
sudo iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 22 -j DNAT --to-destination 172.16.10.10:22
sudo netfilter-persistent save
sudo conntrack -F 2>/dev/null
sudo truncate -s 0 /var/log/suricata/eve.json
sudo truncate -s 0 /var/log/suricata/stats.log 2>/dev/null
sudo python3 -c "import json; p='/etc/mtd/config.json'; c=json.load(open(p)); c['mtd_enabled']=False; c['current_vip']='172.16.10.10'; c['current_https_port']=443; c['current_ssh_port']=22; json.dump(c,open(p,'w'),indent=2)"
sudo python3 -c "import json; p='/var/log/mtd/state.json'; s=json.load(open(p)); s['attackers']={}; s['threat_level']=0.0; s['t_eff']=60.0; s['rotation_count']=0; s['history']=[]; json.dump(s,open(p,'w'),indent=2)"
sudo truncate -s 0 /var/log/mtd/rotations.json 2>/dev/null
sudo systemctl daemon-reload
sudo systemctl start suricata
sleep 3
sudo systemctl start mtd-controller mtd-dashboard
sleep 2
echo "=== Reset complete ==="
```

**What it resets:**
- `mtd_enabled` → False
- `threat_level` → 0
- `attackers` → {} (empty)
- Per-source DNAT rules → removed
- `current_vip` / `current_https_port` / `current_ssh_port` → baseline
- `eve.json` / `rotations.json` → truncated (0 bytes)
- conntrack → flushed

**What it does NOT reset:**
- Suricata stays running (just truncate its log, then restart)
- The iptables baseline DNAT (443→server, 22→server) is restored
- The config pools (VIP, ports) stay
- The server/honeypot VMs are untouched

## 8. Captured Activity Page — `/var/www/dummy/captured.html`

On the honeypot, a presentable HTML page that shows the attacker's captured commands (from Cowrie). Fetches `/cowrie.log` (symlink to the Cowrie log) and displays the last 30 events, newest at top, auto-refreshing every 2s.

**Symlink:** `/var/www/dummy/cowrie.log` → `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` (where Cowrie actually writes).

## 9. rsyslog Forward — honeypot → sensor

### On the honeypot — `/etc/rsyslog.d/99-cowrie-out.conf`

```
module(load="imfile")

input(type="imfile"
      File="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
      Tag="cowrie"
      Facility="local6")

if $syslogtag contains "cowrie" then @@172.16.10.1:514
& stop

input(type="imfile"
      File="/var/log/nginx/dummy-access.log"
      Tag="dummy-access"
      Facility="local6")
if $syslogtag contains "dummy-access" then @@172.16.10.1:514
& stop
```

**Why `contains` not `isequal`:** The imfile-generated syslogtag didn't match `isequal "cowrie:"`. `contains` is broader and works.

**Why the old path:** Cowrie writes to `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` (its default), not `/var/log/cowrie/cowrie.json` (the config we tried to set). The rsyslog imfile tails the old path and forwards to the sensor.

### On the sensor — `/etc/rsyslog.d/49-cowrie-in.conf`

```
$ModLoad imtcp
$InputTCPServerRun 514
$AllowedSender tcp, 172.16.10.0/24
:fromhost-ip, startswith, "172.16.10." /var/log/cowrie/cowrie.json
& stop
```

Receives the forwarded events (Cowrie + nginx dummy-access) and writes to `/var/log/cowrie/cowrie.json`.

## 10. Key gotchas (for cross questions)

| Question | Answer |
|---|---|
| Why is the controller on the sensor, not the server? | If the server falls, the defender doesn't. Suricata + iptables run on the sensor. |
| How does the attacker get redirected? | High-severity Suricata alert → controller flags src_ip → per-source iptables DNAT → honeypot |
| Why does the scan not redirect but brute force does? | Port-scan rule is severity 2 (medium), brute-force is severity 1 (high) |
| How does the legit user stay connected during rotation? | follow-surface.sh polls the dashboard every 2s for the current VIP |
| What's the adaptive policy? | `T_rot = 60 / (1 + threat_level)`, quiet → 60s, attack → ~5s, decays 0.9/tick |
| Why did Suricata not write to eve.json initially? | `-D` (debug) flag disables logging; `af-packet` conflicts with NFQ; missing `*_SERVERS` vars broke ET/Open rules |
| Why does the dashboard show "Internal Server Error"? | Orphaned `{% endif %}` in the template (needs clean re-deploy from repo) |
| How are Cowrie logs forwarded to the sensor? | rsyslog imfile on honeypot tails the Cowrie log, forwards via TCP 514 to sensor's rsyslog |
| Why are the NIC names swapped (ens37/ens38)? | VMware assigned them in a different order than expected. DMZ = ens38, LAN = ens37. |
| Why was NetworkManager disabled? | It regenerates netplan files that override our config, causing IPs to drop on reboot. |
```

**What it resets:**
- `mtd_enabled` → False
- `threat_level` → 0
- `attackers` → {} (empty)
- Per-source DNAT rules → removed
- `current_vip` / `current_https_port` / `current_ssh_port` → baseline
- `eve.json` / `rotations.json` → truncated (0 bytes)
- conntrack → flushed

**What it does NOT reset:**
- Suricata stays running (just truncate its log, then restart)
- The iptables baseline DNAT (443→server, 22→server) is restored
- The config pools (VIP, ports) stay
- The server/honeypot VMs are untouched
