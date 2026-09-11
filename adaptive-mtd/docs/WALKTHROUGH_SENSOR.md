# Sensor VM — Manual Setup Walkthrough

The sensor is the busiest VM: firewall + Suricata inline IPS + the Python MTD controller + the FastAPI dashboard + a lightweight GUI (XFCE + Firefox) so the dashboard can be viewed on the sensor's own console during a self-contained demo (no Windows host browser needed).

Assumes: Ubuntu 24.04 Server installed, static IPs applied, IP forwarding on, `maverick` user with passwordless sudo, SSH working from Windows.

## Prerequisite — temporary internet for apt

Add a NAT adapter (VMnet8) to the sensor VM in VMware, then on the sensor:

```bash
ip -br a                      # find the new NIC, probably ens39 or ens40
sudo dhclient ens39
ping -c 2 8.8.8.8             # must succeed before continuing
sudo apt update
```

## Step 1 — Install system packages + lightweight GUI

```bash
sudo apt install -y \
  iptables netfilter-persistent iptables-persistent \
  suricata suricata-update \
  python3 python3-pip python3-venv \
  rsyslog curl conntrack jq \
  xfce4 xfce4-terminal firefox lightdm
```

`xfce4` + `firefox` + `lightdm` give the sensor a minimal GUI so the dashboard can be viewed on its own console. RAM cost ~300 MB.

Enable the display manager:

```bash
sudo systemctl enable lightdm
sudo systemctl set-default graphical.target
```

To keep it light, boot to text console and run `startx` only when you need the dashboard:

```bash
sudo systemctl set-default multi-user.target   # boot to text console
# then run `startx` when you want the GUI
```

## Step 2 — Verify IP forwarding

```bash
cat /proc/sys/net/ipv4/ip_forward    # must print 1
```

If 0:

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-mtd.conf
sudo sysctl --system
```

## Step 3 — Create MTD directories + write config

```bash
sudo mkdir -p /etc/mtd /var/log/mtd /var/log/cowrie /opt/mtd-client
```

Write the config (single source of truth for controller + dashboard). Use a heredoc:

```bash
sudo tee /etc/mtd/config.json > /dev/null <<'EOF'
{
  "vip_pool": ["172.16.10.10","172.16.10.11","172.16.10.12","172.16.10.13","172.16.10.14"],
  "ssh_port_pool": [22, 2222, 22022, 20222, 22002],
  "https_port_pool": [443, 8443, 4443, 8444, 4444],
  "t_base": 60,
  "decay": 0.9,
  "bump_honeypot": 2,
  "bump_ids_low": 1,
  "bump_ids_med": 1,
  "bump_ids_high": 3,
  "bump_wazuh": 1,
  "threat_cap": 10,
  "tick_seconds": 1,
  "server_ip": "172.16.10.10",
  "honeypot_ip": "172.16.10.20",
  "wan_iface": "ens33",
  "dmz_iface": "ens37",
  "state_path": "/var/log/mtd/state.json",
  "rotation_log": "/var/log/mtd/rotations.json",
  "timeline_log": "/var/log/mtd/timeline.json",
  "suricata_eve": "/var/log/suricata/eve.json",
  "cowrie_log": "/var/log/cowrie/cowrie.json",
  "mtd_enabled": false,
  "current_vip": "172.16.10.10",
  "current_ssh_port": 22,
  "current_https_port": 443
}
EOF
sudo chmod 644 /etc/mtd/config.json
```

## Step 4 — iptables baseline rules (firewall + initial DNAT)

Write `/etc/iptables/rules.v4` with the firewall + NAT rules shown in `ansible/roles/sensor/templates/rules.v4.j2` (substitute ens33/ens37 for your NIC names). Then:

```bash
sudo iptables-restore < /etc/iptables/rules.v4
sudo netfilter-persistent save
sudo systemctl enable --now netfilter-persistent
sudo iptables -t nat -L PREROUTING -n -v | head
```

You should see the two baseline DNAT rules (HTTPS 443, SSH 22).

## Step 5 — Suricata (inline NFQ IPS)

### 5a. Pull ET/Open rules

```bash
sudo suricata-update
```

### 5b. Write custom lab rules

Write `/etc/suricata/rules/mtd.rules` with the 5 SIDs from `ansible/roles/sensor/files/mtd.rules` (T1046 port-scan, T1110 brute-force, T1190 sqlmap UA, T1190 SQLi pattern, T1592 version probe).

### 5c. Write Suricata config

Write `/etc/suricata/suricata.yaml` with the NFQ inline config from `ansible/roles/sensor/templates/suricata.yaml.j2` (substitute your NIC name for the af-packet interface).

### 5d. Enable + start Suricata

```bash
sudo systemctl enable --now suricata
sudo systemctl status suricata --no-pager | head -5
ls -la /var/log/suricata/eve.json
```

## Step 6 — rsyslog to receive Cowrie logs from the honeypot

Write `/etc/rsyslog.d/49-cowrie-in.conf` with the imtcp + AllowedSender + fromhost-ip match for `172.16.10.20` writing to `/var/log/cowrie/cowrie.json`. Then:

```bash
sudo systemctl restart rsyslog
```

## Step 7 — Deploy the MTD controller (from Windows)

From Windows PowerShell:

```powershell
Set-Location "D:\JSACWC\Project\Cursor\adaptive-mtd"
tar -czf ..\mtd_controller.tar.gz --exclude=__pycache__ --exclude=venv mtd_controller
scp ..\mtd_controller.tar.gz sensor:~/
```

On the sensor:

```bash
sudo mkdir -p /opt/mtd-controller
sudo tar -xzf ~/mtd_controller.tar.gz -C /opt/mtd-controller/
ls /opt/mtd-controller/mtd_controller/
```

## Step 8 — Controller venv + systemd unit

```bash
sudo python3 -m venv /opt/mtd-controller/venv
sudo /opt/mtd-controller/venv/bin/pip install --upgrade pip
sudo /opt/mtd-controller/venv/bin/pip install pyyaml
```

Write `/etc/systemd/system/mtd-controller.service` with the unit from `ansible/roles/sensor/templates/mtd-controller.service.j2` (ExecStart points at `/opt/mtd-controller/venv/bin/python -m mtd_controller.controller`). Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mtd-controller
sudo systemctl status mtd-controller --no-pager | head -10
sudo journalctl -u mtd-controller -n 20 --no-pager
```

You should see `[controller] starting. mtd_enabled=False vip=172.16.10.10 ssh=22 https=443`.

## Step 9 — Deploy the dashboard (from Windows)

From Windows PowerShell:

```powershell
Set-Location "D:\JSACWC\Project\Cursor\adaptive-mtd"
tar -czf ..\dashboard.tar.gz --exclude=__pycache__ --exclude=venv dashboard
scp ..\dashboard.tar.gz sensor:~/
```

On the sensor:

```bash
sudo mkdir -p /opt/mtd-dashboard
sudo tar -xzf ~/dashboard.tar.gz -C /opt/mtd-dashboard/
ls /opt/mtd-dashboard/dashboard/
```

## Step 10 — Dashboard venv + systemd unit

```bash
sudo python3 -m venv /opt/mtd-dashboard/venv
sudo /opt/mtd-dashboard/venv/bin/pip install --upgrade pip
sudo /opt/mtd-dashboard/venv/bin/pip install fastapi "uvicorn[standard]" jinja2 requests python-multipart
```

Write `/etc/systemd/system/mtd-dashboard.service` with the unit from `ansible/roles/sensor/templates/mtd-dashboard.service.j2` (ExecStart points at `/opt/mtd-dashboard/venv/bin/uvicorn main:app --host 0.0.0.0 --port 43123`). Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mtd-dashboard
sudo systemctl status mtd-dashboard --no-pager | head -10
```

## Step 11 — Deploy the legit client follow-the-surface loop (from Windows)

From Windows PowerShell:

```powershell
scp "D:\JSACWC\Project\Cursor\adaptive-mtd\client\follow-surface.sh" sensor:/opt/mtd-client/follow-surface.sh
```

On the sensor:

```bash
sudo chmod +x /opt/mtd-client/follow-surface.sh
```

Run manually in a terminal on the sensor's XFCE desktop during the demo (not as a service, so the audience sees it start).

## Step 12 — Verify everything

On the sensor:

```bash
sudo systemctl is-active suricata mtd-controller mtd-dashboard   # three "active"
sudo cat /var/log/mtd/state.json | jq .
sudo iptables -t nat -L PREROUTING -n -v
```

From the sensor's GUI (start XFCE if not already in GUI):

```bash
startx    # if you booted to text console
```

Open Firefox → `https://localhost:43123` → accept the self-signed cert. You should see the dashboard with `mtd_enabled = OFF`, current VIP `172.16.10.10`, ports 22/443, threat_level 0, T_eff 60s. The **Redirected Attackers** panel is empty.

In a second terminal on the sensor, test the client loop:

```bash
bash /opt/mtd-client/follow-surface.sh
```

You should see green `HH:MM:SS 200` lines every 2 seconds. `Ctrl+C` to stop.

## Step 13 — Remove the temporary NAT NIC

In VMware, remove the NAT adapter from the sensor (VM settings → Network Adapter → Remove). Verify DMZ still reachable:

```bash
ping -c 2 172.16.10.10
ping -c 2 172.16.10.20
```

## Step 14 — Snapshot

Snapshot the sensor as `sensor-provisioned`.

## Quick sanity test — trigger a fake attacker redirect

Append a fake high-severity Suricata alert line to `eve.json` with `src_ip` set to `203.0.113.50` and `severity: 1`. Within a few seconds the controller should: bump threat_level by 3, flag `203.0.113.50` as an attacker, install a per-source DNAT rule redirecting that source to the honeypot. Check the dashboard's **Redirected Attackers** panel and `sudo iptables -t nat -L PREROUTING -n -v --line-numbers` (you should see a `-s 203.0.113.50` rule at the top).
