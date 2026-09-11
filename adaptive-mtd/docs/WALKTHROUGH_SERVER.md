# Server VM — Manual Setup Walkthrough

The server is the passive defended target. It just listens on the full VIP pool and the full port pool; the sensor's DNAT picks which is public. No MTD logic, no Suricata, no controller — nothing active.

Assumes: Ubuntu 24.04 Server installed, `maverick` user with sudo, working in the VMware console (no SSH needed).

## Phase 1 — base setup (VM on NAT for internet)

### 1.1 Verify internet + set hostname

```bash
ping -c 2 8.8.8.8
sudo apt update
sudo hostnamectl set-hostname server
sudo nano /etc/hosts
# ensure:
# 127.0.0.1 localhost
# 127.0.1.1 server
# ::1       localhost ip6-localhost ip6-loopback
```

### 1.2 Install packages

```bash
sudo apt install -y nginx openssh-server openssl python3 curl
```

### 1.3 Snapshot

VMware: snapshot `server-phase1-done`.

## Phase 2 — deploy services (VM still on NAT)

### 2.1 Generate self-signed cert

```bash
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/mtd.key \
  -out /etc/nginx/ssl/mtd.crt \
  -days 3650 \
  -subj "/CN=svc.local/O=MTD Lab"
ls -la /etc/nginx/ssl/
```

### 2.2 Write the nginx site config (all HTTPS ports in the pool)

```bash
sudo tee /etc/nginx/sites-available/mtd > /dev/null <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/mtd;
    index index.html;
}

server {
    listen 443 ssl;
    listen 8443 ssl;
    listen 4443 ssl;
    listen 8444 ssl;
    listen 4444 ssl;
    server_name svc.local _;
    root /var/www/mtd;
    index index.html;

    ssl_certificate     /etc/nginx/ssl/mtd.crt;
    ssl_certificate_key /etc/nginx/ssl/mtd.key;
    ssl_protocols        TLSv1.2 TLSv1.3;
    ssl_ciphers          HIGH:!aNULL:!MD5;

    access_log /var/log/nginx/mtd-access.log;
    error_log  /var/log/nginx/mtd-error.log;

    location / {
        try_files $uri $uri/ =404;
    }

    # an injectable-looking endpoint so sqlmap has something to find
    location /login {
        default_type text/plain;
        return 200 "Welcome, $arg_user\n";
    }
}
EOF
```

### 2.3 Create the web root + content

```bash
sudo mkdir -p /var/www/mtd
sudo tee /var/www/mtd/index.html > /dev/null <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MTD Lab - Defended Service</title>
</head>
<body>
<h1>MTD Lab - Defended Service</h1>
<p>This is the protected web service. If you can read this, the surface
is currently pointing at you.</p>
<p>Server: server | VIPs: 172.16.10.10-14</p>
</body></html>
EOF
```

### 2.4 Enable the site, disable the default

```bash
sudo ln -sf /etc/nginx/sites-available/mtd /etc/nginx/sites-enabled/mtd
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t              # test config — must print "test is successful"
sudo systemctl enable --now nginx
sudo systemctl reload nginx
```

### 2.5 Configure sshd to listen on all SSH ports in the pool

```bash
sudo tee /etc/ssh/sshd_config.d/99-mtd.conf > /dev/null <<'EOF'
Port 22
Port 2222
Port 22022
Port 20222
Port 22002
PasswordAuthentication yes
PermitRootLogin no
EOF
sudo systemctl restart ssh
sudo ss -tlnp | grep ssh
```

You should see sshd listening on all 5 ports (22, 2222, 22022, 20222, 22002).

### 2.6 Snapshot

VMware: snapshot `server-phase2-done`.

## Phase 3 — switch to host-only DMZ + bind VIPs

### 3.1 In VMware, set the NIC to host-only VMnet3

sensor VM → Settings → Network Adapter → set to **Host-only: VMnet3** (DMZ).

### 3.2 Boot, find the NIC name

```bash
ip -br a    # note the NIC name, usually ens33
```

### 3.3 Write the static netplan (1 NIC + 4 VIP aliases)

```bash
sudo tee /etc/netplan/01-mtd.yaml > /dev/null <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      addresses:
        - 172.16.10.10/24
        - 172.16.10.11/24
        - 172.16.10.12/24
        - 172.16.10.13/24
        - 172.16.10.14/24
      routes:
        - to: default
          via: 172.16.10.1
EOF
sudo chmod 600 /etc/netplan/01-mtd.yaml
sudo netplan apply
ip -br a
```

You should see all 5 VIPs on `ens33`. (Use `ip a` if `ip -br a` truncates.)

### 3.4 Verify connectivity

From the server:

```bash
ping -c 2 172.16.10.1    # sensor DMZ interface — must reply
ip -br a                  # all 5 VIPs visible
```

From the **sensor**:

```bash
ping -c 2 172.16.10.10
curl -sk http://172.16.10.10:80/    # should return the HTML page
```

From **Windows** (via the sensor jump, or directly if you added a host adapter on VMnet3):

```powershell
ssh server "curl -s http://localhost:80/"
```

### 3.5 Snapshot

VMware: snapshot `server-provisioned`.

## Phase 3 checklist

| # | Done? | Step |
|---|---|---|
| 3.1 | ☐ | NIC set to host-only VMnet3 |
| 3.2 | ☐ | NIC name noted |
| 3.3 | ☐ | Netplan written + applied, 5 VIPs visible |
| 3.4 | ☐ | `ping 172.16.10.1` from server works; sensor can `curl` the server |
| 3.5 | ☐ | Snapshot `server-provisioned` taken |

## What's running on the server now

| Service | Listens on |
|---|---|
| nginx (HTTP) | port 80 on all VIPs |
| nginx (HTTPS) | ports 443, 8443, 4443, 8444, 4444 on all VIPs |
| sshd | ports 22, 2222, 22022, 20222, 22002 on all VIPs |

The server is intentionally dumb — it never changes. The sensor's DNAT picks which VIP:port is public and rotates among them.
