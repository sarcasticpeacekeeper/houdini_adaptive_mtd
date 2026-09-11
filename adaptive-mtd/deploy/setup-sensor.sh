#!/usr/bin/env bash
# Sensor automated setup — runs ON the sensor over SSH.
# Does all of Phase 2: install packages, write config, deploy controller + dashboard,
# set up Suricata + rsyslog + iptables, enable services.
#
# Assumes the repo is available at /mnt/repo (VMware shared folder) OR at /tmp/mtd-lab
# (scp'd tarball). The script auto-detects which.
#
# Run from Windows:
#   ssh sensor "sudo bash /tmp/setup-sensor.sh"
# Or via deploy-sensor.ps1 which scp's this script + the repo and runs it.

set -euo pipefail

# --- locate the repo ---
if [ -d /mnt/repo/mtd_controller ]; then
    REPO=/mnt/repo
elif [ -d /tmp/mtd-lab/mtd_controller ]; then
    REPO=/tmp/mtd-lab
else
    echo "ERROR: repo not found at /mnt/repo or /tmp/mtd-lab" >&2
    echo "Mount the shared folder, or scp the tarball to /tmp/mtd-lab.tar.gz and extract." >&2
    exit 1
fi
echo "Using repo at: $REPO"

# --- 1. packages ---
echo ">>> Installing packages..."
apt update
apt install -y \
  iptables netfilter-persistent iptables-persistent \
  suricata suricata-update \
  python3 python3-pip python3-venv \
  rsyslog curl conntrack jq \
  xfce4 xfce4-terminal firefox lightdm \
  open-vm-tools open-vm-tools-desktop

# --- 2. directories ---
echo ">>> Creating directories..."
mkdir -p /etc/mtd /var/log/mtd /var/log/cowrie
mkdir -p /opt/mtd-controller /opt/mtd-dashboard /opt/mtd-client
mkdir -p /etc/suricata/rules

# --- 3. config.json ---
echo ">>> Writing /etc/mtd/config.json..."
cat > /etc/mtd/config.json <<'CFGEOF'
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
CFGEOF
chmod 644 /etc/mtd/config.json

# --- 4. deploy controller ---
echo ">>> Deploying MTD controller..."
rm -rf /opt/mtd-controller/mtd_controller
cp -r "$REPO/mtd_controller" /opt/mtd-controller/
python3 -m venv /opt/mtd-controller/venv
/opt/mtd-controller/venv/bin/pip install --upgrade pip -q
/opt/mtd-controller/venv/bin/pip install pyyaml -q

cat > /etc/systemd/system/mtd-controller.service <<'SVCEOF'
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
SVCEOF

# --- 5. deploy dashboard ---
echo ">>> Deploying MTD dashboard..."
rm -rf /opt/mtd-dashboard/dashboard
cp -r "$REPO/dashboard" /opt/mtd-dashboard/
python3 -m venv /opt/mtd-dashboard/venv
/opt/mtd-dashboard/venv/bin/pip install --upgrade pip -q
/opt/mtd-dashboard/venv/bin/pip install fastapi "uvicorn[standard]" jinja2 requests -q

cat > /etc/systemd/system/mtd-dashboard.service <<'SVCEOF'
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
SVCEOF

# --- 6. deploy client loop ---
echo ">>> Deploying client follow-the-surface loop..."
cp "$REPO/client/follow-surface.sh" /opt/mtd-client/follow-surface.sh
chmod +x /opt/mtd-client/follow-surface.sh

# --- 7. suricata ---
echo ">>> Setting up Suricata..."
suricata-update
cp "$REPO/ansible/roles/sensor/files/mtd.rules" /etc/suricata/rules/mtd.rules
sed 's/{{ mtd_wan_iface }}/ens33/g' "$REPO/ansible/roles/sensor/templates/suricata.yaml.j2" > /etc/suricata/suricata.yaml
systemctl enable --now suricata

# --- 8. rsyslog ---
echo ">>> Setting up rsyslog for Cowrie..."
cat > /etc/rsyslog.d/49-cowrie-in.conf <<'RSYSEOF'
$ModLoad imtcp
$InputTCPServerRun 514
$AllowedSender tcp, 172.16.10.0/24
:fromhost-ip, isequal, "172.16.10.20" /var/log/cowrie/cowrie.json
& stop
RSYSEOF
systemctl restart rsyslog

# --- 9. iptables ---
echo ">>> Writing iptables baseline rules..."
cat > /etc/iptables/rules.v4 <<'IPTEOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i ens33 -p tcp --dport 22 -s 203.0.113.0/24 -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A FORWARD -p icmp -j ACCEPT
-A INPUT -i ens37 -p tcp --dport 514 -s 172.16.10.20/32 -j ACCEPT
-A FORWARD -i ens33 -o ens37 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass
-A FORWARD -i ens33 -o ens37 -j ACCEPT
-A FORWARD -i ens37 -o ens33 -j ACCEPT
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o ens33 -s 172.16.10.0/24 -j MASQUERADE
-A PREROUTING -i ens33 -p tcp --dport 443 -j DNAT --to-destination 172.16.10.10:443
-A PREROUTING -i ens33 -p tcp --dport 22 -j DNAT --to-destination 172.16.10.10:22
COMMIT
IPTEOF
iptables-restore < /etc/iptables/rules.v4
netfilter-persistent save
systemctl enable --now netfilter-persistent

# --- 10. enable services ---
echo ">>> Enabling MTD services..."
systemctl daemon-reload
systemctl enable --now mtd-controller
systemctl enable --now mtd-dashboard

# --- 11. verify ---
echo ">>> Verify..."
echo "Services:"
systemctl is-active suricata mtd-controller mtd-dashboard
echo "Controller log (last 5 lines):"
journalctl -u mtd-controller -n 5 --no-pager
echo "Dashboard API:"
curl -sk https://localhost:43123/api/surface || echo "(dashboard not ready yet — wait a few seconds)"

echo ""
echo "=========================================="
echo "Sensor setup complete."
echo "Dashboard: https://localhost:43123"
echo "Next: Phase 3 — switch NICs to host-only."
echo "=========================================="
