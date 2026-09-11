# Configuration Report — Server & Honeypot

This report documents every configuration setting on the Server (VM-3) and Honeypot (VM-4) VMs, with the reason for each.

---

## Server (VM-3) — the passive defended target

**Role**: Hosts the real web service (nginx) and SSH service (sshd). Passive — listens on the full VIP pool and port pool; the sensor's DNAT picks which is public.

**OS**: Ubuntu 24.04 Server
**IP**: 172.16.10.10/24 (primary) + 4 VIP aliases (.11–.14)
**NIC**: ens33 on VMnet3 (DMZ)
**Gateway**: 172.16.10.1 (sensor DMZ)

### Network (netplan)

**File**: `/etc/netplan/01-mtd.yaml`

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      addresses:
        - 172.16.10.10/24   # primary IP
        - 172.16.10.11/24   # VIP alias
        - 172.16.10.12/24   # VIP alias
        - 172.16.10.13/24   # VIP alias
        - 172.16.10.14/24   # VIP alias
      routes:
        - to: default
          via: 172.16.10.1   # sensor DMZ is the gateway
```

**Why**: The server binds to all 5 VIPs so the sensor's DNAT can point the public surface at any of them. The sensor rotates the DNAT target; the server doesn't change. The gateway is the sensor (DMZ), so the server can reach the WAN through it.

### nginx (web service)

**File**: `/etc/nginx/sites-available/mtd`

```nginx
server {
    listen 80 default_server;          # HTTP on port 80
    listen [::]:80;
    server_name _;
    root /var/www/mtd;               # web root
    index index.html;
    charset utf-8;
}

server {
    listen 443 ssl;                  # HTTPS on all 5 ports in the pool
    listen 8443 ssl;
    listen 4443 ssl;
    listen 8444 ssl;
    listen 4444 ssl;
    server_name svc.local _;
    root /var/www/mtd;
    index index.html;
    charset utf-8;

    ssl_certificate     /etc/nginx/ssl/mtd.crt;   # self-signed cert
    ssl_certificate_key /etc/nginx/ssl/mtd.key;
    ssl_protocols        TLSv1.2 TLSv1.3;
    ssl_ciphers          HIGH:!aNULL:!MD5;

    access_log /var/log/nginx/mtd-access.log;   # access log (for the demo proof)
    error_log  /var/log/nginx/mtd-error.log;

    location / { try_files $uri $uri/ =404; }
    location /login {                       # injectable-looking endpoint for sqlmap
        default_type text/plain;
        return 200 "Welcome, $arg_user\n";
    }
}
```

**Why**:
- `listen 443/8443/4443/8444/4444 ssl` — nginx listens on **all 5 HTTPS ports** in the pool. The sensor's DNAT picks one to be public; the server answers on all of them. No per-rotation server action.
- `listen 80` — HTTP on port 80 (not rotated, just for completeness).
- `root /var/www/mtd` — the web root.
- `ssl_certificate /etc/nginx/ssl/mtd.crt` — self-signed cert (generated at install time, 10-year validity). The demo uses `curl -k` (insecure) to accept it.
- `access_log /var/log/nginx/mtd-access.log` — the access log. Used in the demo proof: the server's log shows the benign request, not the attacker's post-attack one.
- `location /login` — an injectable-looking endpoint (`return 200 "Welcome, $arg_user"`) so sqlmap has something to find in the web exploit phase. It echoes the `user` parameter, which looks injectable.

**Web content**: `/var/www/mtd/index.html`

```html
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Internal Portal - Login</title>
<style>
body{font-family:sans-serif;background:#f5f5f5;padding:40px}
.box{max-width:320px;margin:auto;background:white;padding:24px;border-radius:6px;box-shadow:0 1px 3px #999}
input{width:100%;padding:8px;margin:6px 0;box-sizing:border-box}
button{width:100%;padding:10px;background:#0d6efd;color:white;border:none;border-radius:4px}
</style>
</head>
<body>
<div class="box">
<h2>Internal Portal</h2>
<form method="post" action="/login">
<input name="user" placeholder="username"><br>
<input name="pass" type="password" placeholder="password"><br>
<button type="submit">Sign in</button>
</form>
<p style="color:#888;font-size:12px">v2.1.4 - server - authorized users only</p>
</div>
</body>
</html>
```

**Why**: Identical to the honeypot's page (same "Internal Portal - Login" form) so the attacker can't tell which backend they hit only by IP/port (which rotates), not by the page content. The footer label (`v2.1.4 - server`) reveals the backend to the audience.

### sshd (SSH service)

**File**: `/etc/ssh/sshd_config.d/99-mtd.conf`

```
Port 22
Port 2222
Port 22022
Port 20222
Port 22002
PasswordAuthentication yes
PermitRootLogin no
```

**Why**: sshd listens on **all 5 SSH ports** in the pool. The sensor's DNAT picks one to be public; the server answers on all of them. `PasswordAuthentication yes` so hydra has something to brute-force. `PermitRootLogin no` for safety.

**Note**: On Ubuntu 24.04, `ssh.socket` (systemd socket activation) holds port 22 by default. To make sshd listen on all 5 ports, we disabled `ssh.socket` and `ssh.service` and run sshd as a normal service (`systemctl enable --now ssh.service`). This is documented in `docs/WALKTHROUGH_SERVER.md`.

### Self-signed cert

**Generated at install time**:
```bash
sudo openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/mtd.key \
  -out /etc/nginx/ssl/mtd.crt \
  -days 3650 \
  -subj "/CN=svc.local/O=MTD Lab"
```

**Why**: Self-signed (no CA) — the lab is isolated, no real domain. 10-year validity so it doesn't expire during the demo. `curl -k` accepts the warning.

---

## Honeypot (VM-4) — the decoy

**Role**: Runs two decoys — Cowrie (SSH) and nginx (dummy website). When the controller redirects a detected attacker to the honeypot, the attacker hits the decoy instead of the real server. The page is identical, so the attacker can't tell only by the footer label (`v2.1.4 - honeypot`).

**OS**: Ubuntu 24.04 Server
**IP**: 172.16.10.20/24
**NIC**: ens33 on VMnet3 (DMZ, same as server)
**Gateway**: 172.16.10.1 (sensor DMZ)

### Network (netplan)

**File**: `/etc/netplan/01-mtd.yaml`

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      addresses: [172.16.10.20/24]
      routes:
        - to: default
          via: 172.16.10.1
```

**Why**: Single IP on the DMZ. The honeypot is never publicly exposed by default — the attacker only reaches it when the controller redirects them. Same gateway (sensor DMZ).

### Cowrie (SSH decoy)

**Config**: `/home/cowrie/cowrie/etc/cowrie.cfg`

```ini
[shell]
hostname = srv-prod-01              # fake hostname (looks like the real server)
log_path = /home/cowrie/cowrie/var/log/cowrie
download_path = /home/cowrie/cowrie/var/lib/cowrie/downloads
interactive = true

[ssh]
enabled = true
listen_endpoints = tcp:22:interface=0.0.0.0   # SSH on port 22 (single endpoint)
ssh_version_string = OpenSSH_8.4p1 Debian-5+deb11u1  # fake banner

[telnet]
enabled = false

[output]
jsonlog = /var/log/cowrie/cowrie.json    # JSON log (moved to /var/log for AppArmor)

[output_jsonlog]
epoch_timestamp = true
```

**Why**:
- `hostname = srv-prod-01` — fake hostname that looks like a real production server, so the attacker thinks they hit the real thing.
- `listen_endpoints = tcp:22` — single SSH port (port 22). We removed the duplicate `listen_endpoints` line (configparser rejects duplicate keys) and the second port (2222) — port 22 is enough for the demo.
- `jsonlog = /var/log/cowrie/cowrie.json` — JSON log. Moved to `/var/log/cowrie/` (AppArmor-allowed path) because rsyslog's `imfile` module couldn't read `/home/cowrie/...` (AppArmor blocks rsyslogd from `/home/`).
- `ssh_version_string = OpenSSH_8.4p1 Debian-5+deb11u1` — fake SSH banner.

**systemd unit**: `/etc/systemd/system/cowrie.service`

```ini
[Unit]
Description=Cowrie SSH Honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/cowrie
Environment=PATH=/home/cowrie/cowrie/venv/bin:/usr/bin:/bin
AmbientCapabilities=CAP_NET_BIND_SERVICE    # bind port 22 without root
ExecStart=/home/cowrie/cowrie/venv/bin/twistd --nodaemon --umask=0022 --pidfile /home/cowrie/cowrie/var/run/cowrie.pid --logger cowrie.python.logfile.logger cowrie
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

**Why**:
- `Type=simple` + `twistd --nodaemon` — twistd runs in the foreground (systemd tracks it). Cowrie's `cowrie start` daemonizes and exits, which breaks `Type=simple`; running twistd directly with `--nodaemon` keeps it in the foreground.
- `AmbientCapabilities=CAP_NET_BIND_SERVICE` — grants the cowrie user the capability to bind port 22 (privileged port) without running as root. This is the fix for `Permission denied` on port 22.
- `Environment=PATH=...venv/bin:...` — so `twistd` can find its dependencies.

### nginx (dummy website)

**File**: `/etc/nginx/sites-available/dummy`

```nginx
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    root /var/www/dummy;               # dummy web root
    index index.html;
    charset utf-8;
    ssl_certificate     /etc/nginx/ssl/dummy.crt;   # separate self-signed cert
    ssl_certificate_key /etc/nginx/ssl/dummy.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    access_log /var/log/nginx/dummy-access.log;   # access log (for the demo proof)
    error_log  /var/log/nginx/dummy-error.log;
    location / { try_files $uri $uri/ =404; }
    location /login { return 200 "Login submitted.\n"; }
}
```

**Why**:
- `listen 80` + `listen 443 ssl` — HTTP and HTTPS. The attacker (redirected) hits port 443.
- `root /var/www/dummy` — dummy web root (separate from the server's `/var/www/mtd`).
- `ssl_certificate /etc/nginx/ssl/dummy.crt` — separate self-signed cert (so the cert fingerprint differs from the server's, but the page content is identical).
- `access_log /var/log/nginx/dummy-access.log` — the access log. Used in the demo proof: the honeypot's log shows the attacker's post-attack request.

**Web content**: `/var/www/dummy/index.html`

```html
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Internal Portal - Login</title>
<style>
body{font-family:sans-serif;background:#f5f5f5;padding:40px}
.box{max-width:320px;margin:auto;background:white;padding:24px;border-radius:6px;box-shadow:0 1px 3px #999}
input{width:100%;padding:8px;margin:6px 0;box-sizing:border-box}
button{width:100%;padding:10px;background:#0d6efd;color:white;border:none;border-radius:4px}
</style>
</head>
<body>
<div class="box">
<h2>Internal Portal</h2>
<form method="post" action="/login">
<input name="user" placeholder="username"><br>
<input name="pass" type="password" placeholder="password"><br>
<button type="submit">Sign in</button>
</form>
<p style="color:#888;font-size:12px">v2.1.4 - honeypot - authorized users only</p>
</div>
</body>
</html>
```

**Why**: Identical to the server's page (same "Internal Portal - Login" form, same CSS) so the attacker can't tell which backend they hit only by the footer label (`v2.1.4 - honeypot`). The deception is complete.

### rsyslog (forward Cowrie logs to the sensor)

**File**: `/etc/rsyslog.d/99-cowrie-out.conf`

```
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
```

**Why**:
- `module(load="imfile")` — rsyslog's imfile module tails the cowrie.json file and the nginx dummy-access log.
- `if $syslogtag contains "cowrie"` — match by tag (not `isequal`, which didn't match imfile-generated tags). `contains` is broader and works.
- `@@172.16.10.1:514` — forward via TCP to the sensor's rsyslog on port 514. The sensor's rsyslog receives and writes to `/var/log/cowrie/cowrie.json`.
- Cowrie writes to `/var/log/cowrie/cowrie.json` (AppArmor-allowed path), not `/home/cowrie/...` (rsyslog couldn't read there).

---

## How the server and honeypot work together

| Aspect | Server | Honeypot |
|---|---|---|
| IP | 172.16.10.10 (+ VIPs .11–.14) | 172.16.10.20 |
| Web root | `/var/www/mtd` | `/var/www/dummy` |
| Page | Identical "Internal Portal - Login" | Identical |
| Footer label | `v2.1.4 - server` | `v2.1.4 - honeypot` |
| SSH | sshd (real) on ports 22,2222,22022,20222,22002 | Cowrie (fake) on port 22 |
| Access log | `/var/log/nginx/mtd-access.log` | `/var/log/nginx/dummy-access.log` |
| Logs to sensor | (no — server logs stay local) | rsyslog → sensor `/var/log/cowrie/cowrie.json` |

The **only** difference the attacker can see is the footer label (`server` vs `honeypot`) and the IP/port (which rotates). The page content is identical — that's the deception.
