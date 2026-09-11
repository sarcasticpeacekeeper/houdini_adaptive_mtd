# Honeypot VM — Manual Setup Walkthrough

The honeypot runs two decoys + a log shipper:
- **Cowrie** — SSH medium-interaction honeypot (fake SSH server that logs every login/command/session)
- **nginx** — dummy website (fake login page) that redirected attackers hit
- **rsyslog** — ships Cowrie JSON + nginx access logs to the sensor (TCP 514)

The honeypot is never publicly exposed by default. The attacker only reaches it when the controller redirects them there (after Suricata flags them).

Assumes: Ubuntu 24.04 Server installed, `maverick` (or `ubuntu`) user with sudo, working in the VMware console (no SSH needed).

## Phase 1 — base setup (VM on NAT for internet)

### 1.1 Verify internet + set hostname

```bash
ping -c 2 8.8.8.8
sudo apt update
sudo hostnamectl set-hostname honeypot
sudo nano /etc/hosts
# ensure:
# 127.0.0.1 localhost
# 127.0.1.1 honeypot
# ::1       localhost ip6-localhost ip6-loopback
```

### 1.2 Install packages

```bash
sudo apt install -y \
  python3 python3-venv python3-dev \
  git curl rsyslog authbind \
  nginx openssl jq
```

### 1.3 Snapshot

VMware: snapshot `honeypot-phase1-done`.

## Phase 2 — deploy services (VM still on NAT)

### 2.1 Create the cowrie user

```bash
sudo useradd -m -s /bin/bash cowrie
```

### 2.2 Clone Cowrie

```bash
sudo -u cowrie git clone https://github.com/cowrie/cowrie /home/cowrie/cowrie
ls /home/cowrie/cowrie
```

### 2.3 Create the Python venv + install deps

```bash
sudo -u cowrie python3 -m venv /home/cowrie/cowrie/venv
sudo -u cowrie /home/cowrie/cowrie/venv/bin/pip install --upgrade pip
sudo -u cowrie /home/cowrie/cowrie/venv/bin/pip install -r /home/cowrie/cowrie/requirements.txt
sudo -u cowrie /home/cowrie/cowrie/venv/bin/pip install -e /home/cowrie/cowrie/
```

### 2.4 Write the Cowrie config

```bash
sudo tee /home/cowrie/cowrie/etc/cowrie.cfg > /dev/null <<'EOF'
[shell]
hostname = srv-prod-01
log_path = /home/cowrie/cowrie/var/log/cowrie
download_path = /home/cowrie/cowrie/var/lib/cowrie/downloads
interactive = true

[ssh]
enabled = true
listen_endpoints = tcp:22:interface=0.0.0.0
ssh_version_string = OpenSSH_8.4p1 Debian-5+deb11u1

[telnet]
enabled = false

[output]
jsonlog = /home/cowrie/cowrie/var/log/cowrie/cowrie.json

[output_jsonlog]
epoch_timestamp = true
EOF
sudo chown cowrie:cowrie /home/cowrie/cowrie/etc/cowrie.cfg
```

### 2.5 Allow cowrie to bind port 22 (authbind)

```bash
sudo touch /etc/authbind/byport/22
sudo chown cowrie:cowrie /etc/authbind/byport/22
sudo chmod 755 /etc/authbind/byport/22
```

### 2.6 Write the Cowrie systemd unit

```bash
sudo tee /etc/systemd/system/cowrie.service > /dev/null <<'EOF'
[Unit]
Description=Cowrie SSH Honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie
ExecStart=/home/cowrie/cowrie/venv/bin/python -m cowrie --config /home/cowrie/cowrie/etc/cowrie.cfg start
ExecStop=/home/cowrie/cowrie/venv/bin/python -m cowrie stop
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cowrie
sudo systemctl status cowrie --no-pager | head -5
```

Should say `active (running)`. Verify it's listening:

```bash
sudo ss -tlnp | grep -E ':(22|2222) '
```

Should show cowrie on ports 22 and 2222.

### 2.7 Create the dummy website (for redirected attackers)

```bash
sudo mkdir -p /var/www/dummy
sudo tee /var/www/dummy/index.html > /dev/null <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>MTD Lab - Defended Service</title></head>
<body>
<h1>MTD Lab - Defended Service</h1>
<p>This is the protected web service. If you can read this, the surface
is currently pointing at you.</p>
<p>Server: server | VIPs: 172.16.10.10-14</p>
</body></html>
EOF
```

### 2.8 Self-signed cert for the dummy site

```bash
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/dummy.key \
  -out /etc/nginx/ssl/dummy.crt \
  -days 3650 \
  -subj "/CN=svc.local/O=MTD Lab Honeypot"
```

### 2.9 nginx dummy site config

```bash
sudo tee /etc/nginx/sites-available/dummy > /dev/null <<'EOF'
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    root /var/www/dummy;
    index index.html;
    charset utf-8;

    ssl_certificate     /etc/nginx/ssl/dummy.crt;
    ssl_certificate_key /etc/nginx/ssl/dummy.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    access_log /var/log/nginx/dummy-access.log;
    error_log  /var/log/nginx/dummy-error.log;

    location / { try_files $uri $uri/ =404; }
    location /login { return 200 "Login submitted.\n"; }
}
EOF

sudo ln -sf /etc/nginx/sites-available/dummy /etc/nginx/sites-enabled/dummy
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl reload nginx
sudo ss -tlnp | grep -E ':(80|443) '
```

Should show nginx on 80 and 443.

### 2.10 rsyslog — ship logs to the sensor

```bash
sudo tee /etc/rsyslog.d/99-cowrie-out.conf > /dev/null <<'EOF'
module(load="imfile")

input(type="imfile"
      File="/var/log/cowrie/cowrie.json"
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
EOF
sudo systemctl restart rsyslog
```

Note: `172.16.10.1` is the sensor's DMZ IP. This only works once both VMs are on VMnet3 (Phase 3). For now the file is just written.

### 2.11 Snapshot

VMware: snapshot `honeypot-phase2-done`.

## Phase 3 — switch to host-only DMZ

### 3.1 In VMware, set the NIC to host-only VMnet3

honeypot VM -> Settings -> Network Adapter -> set to **Host-only: VMnet3**.

### 3.2 Boot, find the NIC name

```bash
ip -br a    # usually ens33
```

### 3.3 Write the static netplan

```bash
sudo tee /etc/netplan/01-mtd.yaml > /dev/null <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      addresses: [172.16.10.20/24]
      routes:
        - to: default
          via: 172.16.10.1
EOF
sudo chmod 600 /etc/netplan/01-mtd.yaml
sudo netplan apply
ip -br a
```

Should show `ens33 UP 172.16.10.20/24`.

### 3.4 Verify connectivity

From the **honeypot**:

```bash
ping -c 2 172.16.10.1    # sensor DMZ — must reply
ping -c 2 172.16.10.10    # server (same segment)
```

From the **sensor**:

```bash
ping -c 2 172.16.10.20    # honeypot — must reply
```

### 3.5 Verify rsyslog shipping works

On the **honeypot**, trigger a fake cowrie event (or just restart cowrie — it logs a session start):

```bash
sudo systemctl restart cowrie
```

On the **sensor**, check the log arrived:

```bash
sudo tail -f /var/log/cowrie/cowrie.json
```

You should see cowrie JSON lines arriving (rsyslog is forwarding them). `Ctrl+C` to stop.

### 3.6 Snapshot

VMware: snapshot `honeypot-provisioned`.

## Phase 3 checklist

| # | Done? | Step |
|---|---|---|
| 3.1 | ☐ | NIC set to host-only VMnet3 |
| 3.2 | ☐ | NIC name noted |
| 3.3 | ☐ | Netplan written + applied, 172.16.10.20 visible |
| 3.4 | ☐ | Honeypot <-> sensor ping works; honeypot <-> server ping works |
| 3.5 | ☐ | rsyslog forwarding cowrie logs to sensor (verify on sensor) |
| 3.6 | ☐ | Snapshot `honeypot-provisioned` taken |

## What's running on the honeypot now

| Service | Listens on | Logs to |
|---|---|---|
| Cowrie (SSH decoy) | ports 22, 2222 on all IPs | /home/cowrie/cowrie/var/log/cowrie/cowrie.json -> rsyslog -> sensor |
| nginx (dummy website) | ports 80, 443 on all IPs | /var/log/nginx/dummy-access.log -> rsyslog -> sensor |
| rsyslog | ships to sensor TCP 514 | - |
