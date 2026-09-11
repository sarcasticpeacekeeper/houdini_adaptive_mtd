# VM Setup — Service Install Guide (narrative)

This is the narrative version of what each Ansible role does. Use it to understand the lab, to debug a failed Ansible run, or to install a piece by hand.

## Sensor (VM-2) — the brain

The sensor is the busiest VM. It runs four things:

### 1. iptables firewall + DNAT

The sensor is the gateway for the DMZ. iptables does three jobs:

- **Forwarding firewall**: drop everything by default, allow established + specific flows (DMZ → WAN replies, WAN → DMZ only via DNAT).
- **DNAT**: the public-facing surface. One rule per service points the public port at the current VIP:internal-port on the server. The MTD controller rewrites this rule on every rotation.
- **Egress drop**: anything from the sensor destined to `203.0.113.1` (the placeholder upstream) is dropped — the "internet" is simulated, no real egress.

The Ansible role `roles/sensor/tasks/iptables.yml` writes a baseline ruleset to `/etc/iptables/rules.v4` and enables `netfilter-persistent`. The controller later edits only the DNAT lines.

### 2. Suricata inline IPS (NFQUEUE)

Suricata inspects WAN→DMZ traffic inline. The sensor's FORWARD chain sends candidate flows to NFQUEUE, where Suricata inspects and either accepts or drops.

Install:
```bash
sudo apt install -y suricata
```

Run suricata-update to pull the ET/Open ruleset, then add the lab's custom rules (port-scan, brute-force, web-attack signatures — see `docs/MITRE_MAPPING.md` for SIDs). Run mode = `nfq` (inline), bound to NFQUEUE queue 0.

The Ansible role writes `/etc/suricata/suricata.yaml` with `nfq` mode and a custom rule file `/etc/suricata/rules/mtd.rules`, then enables the `suricata.service`.

### 3. Python MTD controller

The controller is a Python 3 application in `/opt/mtd-controller/` with these modules:

- `config.py` — pools, T_base, decay, mtd_enabled toggle (read from `/etc/mtd/config.json`).
- `state.py` — current surface (VIP, ports) + rotation history, written to `/var/log/mtd/state.json`.
- `policy.py` — threat_level state machine. Reads events, applies bumps + decay, computes T_eff.
- `suricata_reader.py` — tails `/var/log/suricata/eve.json`, emits normalized events to the policy.
- `cowrie_reader.py` — tails `/var/log/cowrie/cowrie.json` (rsyslog-shipped from the honeypot), emits events to the policy.
- `rotator.py` — applies iptables DNAT changes to rotate VIP/port.
- `controller.py` — main loop: events → policy → maybe rotate → log + push to dashboard.

Installed as a systemd service `mtd-controller.service` running as root (it needs iptables).

### 4. FastAPI dashboard

A small FastAPI app in `/opt/mtd-dashboard/` served by uvicorn on port 43123. Shows:
- Current VIP, current SSH port, current HTTPS port
- threat_level, T_eff, last rotation timestamp
- Rotation log (last 50 events)
- `mtd_enabled` toggle button (POSTs to the controller)
- A/B comparison table (rendered after both runs)

## Server (VM-3) — the passive target

The server is intentionally dumb. At install time it's configured to listen on the full VIP pool and the full port pool, then left alone. The sensor's DNAT picks which is public.

### nginx (HTTP + HTTPS)

A single server block listens on every HTTPS port in the pool:

```nginx
server {
    listen 443 ssl;
    listen 8443 ssl;
    listen 4443 ssl;
    listen 8444 ssl;
    listen 4444 ssl;
    ssl_certificate     /etc/nginx/ssl/mtd.crt;
    ssl_certificate_key /etc/nginx/ssl/mtd.key;
    root /var/www/mtd;
    index index.html;
}
```

A second block does the same for HTTP port 80 (not rotated — just for completeness). nginx binds to `0.0.0.0` so it answers on every VIP the server has.

### openssh-server on multiple ports

The simplest reliable approach: use `StreamLocalTarget` is overkill. Instead, run multiple `sshd` instances via a systemd template, OR use the `Port` directive multiple times in `sshd_config`:

```
Port 22
Port 2222
Port 22022
Port 20222
Port 22002
```

Then `sudo systemctl restart ssh`. Verify with `ss -tlnp | grep ssh` — all five ports should show.

### VIP pool

The five VIPs (`172.16.10.10`–`.14`) are bound to `ens33` via netplan (see `docs/VMWARE_SETUP.md`). They persist across reboots.

## Honeypot (VM-4) — the tripwire

### Cowrie (SSH medium-interaction)

Cowrie runs a fake SSH server on port 22 (and optionally 2222). It logs every login attempt — successful or not — to `/var/log/cowrie/cowrie.json`. The honeypot's IP (`172.16.10.20`) is reachable from the DMZ but never exposed publicly by the sensor's DNAT. The attacker only lands on it if the controller deliberately redirects brute-force traffic there (the "honeypot trip" response).

Install (Ansible automates this):
```bash
sudo apt install -y python3 python3-venv git
sudo useradd -m -s /bin/bash cowrie
sudo -u cowrie git clone https://github.com/cowrie/cowrie /home/cowrie/cowrie
cd /home/cowrie/cowrie
sudo -u cowrie python3 -m venv venv
sudo -u cowrie venv/bin/pip install -r requirements.txt
```

Configure `/home/cowrie/cowrie/etc/cowrie.cfg` to listen on port 22, with a fake hostname that looks like the real server (e.g. `srv-prod-01`). Run as a systemd service `cowrie.service`.

### rsyslog forwarding to the sensor

The honeypot ships cowrie JSON to the sensor via syslog. In `/etc/rsyslog.d/99-cowrie.conf`:

```
if $programname == 'cowrie' then @@172.16.10.1:514
& stop
```

On the sensor, rsyslog listens on TCP 514 (DMZ interface only) and writes to `/var/log/cowrie/cowrie.json`. The controller's `cowrie_reader.py` tails that file.

## Attacker (VM-1) — the threat

### Tools

Kali ships with everything we need. Ansible just verifies and installs any missing ones:

```bash
sudo apt install -y nmap hydra sqlmap curl python3
```

### Attack script

`/opt/mtd-attacker/run_attack.py` — one script, `--phase` flags, deterministic ordering, MITRE-tagged output. Phases: `scan`, `brute`, `web`, `ssh`, `all`. See `attacker/run_attack.py` in the repo.

The script is intentionally simple — it doesn't adapt to rotations. That's the whole point: the attacker's recon goes stale because the script doesn't know the surface moved.

## What's NOT installed (out of scope)

- **Wazuh SIEM** — stubbed in the controller (`wazuh_enabled: false`). Future: add a 5th VM running Wazuh single-node, ship Suricata/Cowrie/rotation logs to it.
- **Client VM** — the legit-user `curl` loop can be run from the Windows host during the demo. Future: add a 6th VM running just the loop.
- **Kernel-level MTD, ASLR, app mutation** — explicitly out of scope. Only IP + port diversity.
