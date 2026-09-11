# VM Setup Guide (VMware Workstation Pro, Windows host)

This is the human-readable version of what the Ansible roles automate. Use it as a reference while you build the VMs manually, or as a troubleshooting guide if Ansible fails on a step.

## Pre-flight (do once on the Windows host)

### Download ISOs

| ISO | Where | File |
|---|---|---|
| Kali 2026 (attacker) | https://www.kali.org/get-kali/ → Installer Images → 64-bit (amd64) | `kali-linux-2026.X-installer-amd64.iso` |
| Ubuntu 24.04 LTS Server (sensor/server/honeypot) | https://cdimage.ubuntu.com/releases/24.04/release/ | `ubuntu-24.04.X-live-server-amd64.iso` |

Verify SHA256 from the same download pages.

### Create 3 host-only VMnets in Virtual Network Editor

Open VMware → Edit → Virtual Network Editor → Change Settings (admin). Add three host-only networks:

| VMnet | Subnet | Type | DHCP | Connect a host virtual adapter |
|---|---|---|---|---|
| VMnet2 | 203.0.113.0/24 | Host-only | OFF | YES (so Windows can SSH to attacker + sensor WAN) |
| VMnet3 | 172.16.10.0/24 | Host-only | OFF | NO (use sensor as jump host) |
| VMnet4 | 192.168.10.0/24 | Host-only | OFF | NO (reserved for future Client VM) |

If VMnet2/3/4 are taken, use the next free numbers (VMnet5/6/7) — keep the mapping consistent across all VMs.

### Set the Windows host adapter IP on VMnet2

```powershell
# run as admin
Remove-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet2" -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet2" -IPAddress 203.0.113.1 -PrefixLength 24
```

### Open the Windows firewall for the lab

```powershell
# run as admin
New-NetFirewallRule -DisplayName "MTD Lab - ICMP Inbound"  -Direction Inbound  -Action Allow -Protocol ICMPv4 -IcmpType Any -Profile Any
New-NetFirewallRule -DisplayName "MTD Lab - ICMP Outbound" -Direction Outbound -Action Allow -Protocol ICMPv4 -IcmpType Any -Profile Any
New-NetFirewallRule -DisplayName "MTD Lab - SSH Inbound"    -Direction Inbound  -Action Allow -Protocol TCP -LocalPort 22 -Profile Any
```

### Disable Cloudflare WARP (or split-tunnel the lab subnets)

Cloudflare WARP's WireGuard filter breaks host→VM traffic on VMware host-only networks. Quit WARP from the tray before working on the lab, or add split-tunnel exclusions for `203.0.113.0/24`, `172.16.10.0/24`, `192.168.10.0/24`.

## Per-VM specs

| VM | OS | RAM | vCPU | Disk | NICs (VMnet) | Static IP |
|---|---|---|---|---|---|---|
| 1 Attacker | Kali 2026 | 3 GB | 2 | 20 GB | 1 × VMnet2 | eth0: 203.0.113.50/24, gw 203.0.113.1 |
| 2 Sensor | Ubuntu 24.04 | 2 GB | 2 | 20 GB | 3: VMnet2/VMnet3/VMnet4 in order | ens33: 203.0.113.2/24, ens37: 172.16.10.1/24, ens38: 192.168.10.1/24 |
| 3 Server | Ubuntu 24.04 | 1 GB | 1 | 15 GB | 1 × VMnet3 | ens33: 172.16.10.10/24 + VIPs .11–.14, gw 172.16.10.1 |
| 4 Honeypot | Ubuntu 24.04 | 1 GB | 1 | 15 GB | 1 × VMnet3 | ens33: 172.16.10.20/24, gw 172.16.10.1 |

Total VM RAM: 7 GB. On a 24 GB host, leaves ~17 GB for Windows + overhead.

## Per-VM install

### Ubuntu (sensor, server, honeypot)

For each: New VM → Custom → "I will install the OS later" → Linux / Ubuntu 64-bit → set RAM/CPU/disk/NICs per table → mount the Ubuntu 24.04 ISO → boot.

Installer choices (same for all three):
- Language: English
- Installer base: **Ubuntu Server (minimized)** — saves ~300 MB
- Network: skip auto-config (we set static post-install)
- Storage: "Use an entire disk" + LVM, no encryption
- Profile: username `maverick`, hostname = VM role (sensor/server/honeypot), pick a password and remember it
- SSH: **YES, install OpenSSH server**
- Snaps: uncheck all

### Kali (attacker)

New VM → Custom → "I will install the OS later" → Linux / Debian 10.x 64-bit (VMware has no Kali entry) → set RAM/CPU/disk/NIC → mount Kali ISO → boot → **Install** (text installer, no desktop, saves 1.5 GB RAM).

Installer choices:
- Hostname: `attacker`
- Username: `maverick`, pick a password
- Partitioning: "Guided - use entire disk" → single file
- Software selection: **only** "Kali Linux default install" + "SSH server". Uncheck desktop environments.
- Install GRUB to `/dev/sda`

## Post-install network config

### Sensor — `/etc/netplan/01-mtd.yaml`

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33:
      addresses: [203.0.113.2/24]
      routes:
        - to: default
          via: 203.0.113.1
    ens37:
      addresses: [172.16.10.1/24]
    ens38:
      addresses: [192.168.10.1/24]
```

```bash
sudo chmod 600 /etc/netplan/01-mtd.yaml
sudo netplan apply
```

> **NIC name note:** VMware assigns `ens33`/`ens37`/`ens41` by adapter order, but the 3rd NIC sometimes shows up as `ens38`. Run `ip -br a` after first boot and use the actual names. Substitute everywhere.

### Server — `/etc/netplan/01-mtd.yaml` (1 NIC + 4 VIP aliases)

```yaml
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
```

```bash
sudo chmod 600 /etc/netplan/01-mtd.yaml
sudo netplan apply
```

### Honeypot — `/etc/netplan/01-mtd.yaml`

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

```bash
sudo chmod 600 /etc/netplan/01-mtd.yaml
sudo netplan apply
```

### Attacker (Kali) — uses nmcli, not netplan

```bash
nmcli con show    # find the connection name, e.g. "Wired connection 1"
sudo nmcli con mod "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses 203.0.113.50/24 \
  ipv4.gateway 203.0.113.1
sudo nmcli con up "Wired connection 1"
```

## Enable IP forwarding on the Sensor

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-mtd.conf
sudo sysctl --system
sysctl net.ipv4.ip_forward    # must print = 1
```

## Create the maverick user + passwordless sudo (on each VM)

If you used `maverick` as the install username, skip to the sudoers step. Otherwise:

```bash
sudo useradd -m -s /bin/bash maverick
sudo passwd maverick
sudo usermod -aG sudo maverick
echo 'maverick ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/maverick
sudo chmod 440 /etc/sudoers.d/maverick
sudo visudo -c -f /etc/sudoers.d/maverick    # must print "parsed OK"
```

## Set hostname + /etc/hosts (on each VM)

```bash
sudo hostnamectl set-hostname <sensor|server|honeypot|attacker>
sudo nano /etc/hosts
# ensure these lines:
# 127.0.0.1 localhost
# 127.0.1.1 <hostname>
# ::1       localhost ip6-localhost ip6-loopback
```

## Enable SSH server (on each VM)

```bash
sudo apt update && sudo apt install -y openssh-server
sudo systemctl enable --now ssh
```

## Push SSH key from Windows

On the Windows host (PowerShell):

```powershell
New-Item -ItemType Directory -Path "$HOME\.ssh" -Force | Out-Null
ssh-keygen -t ed25519 -f "$HOME\.ssh\mtd_lab_key" -N '""'

# push to attacker + sensor (direct, on VMnet2)
type $HOME\.ssh\mtd_lab_key.pub | ssh maverick@203.0.113.50 -o StrictHostKeyChecking=no "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
type $HOME\.ssh\mtd_lab_key.pub | ssh maverick@203.0.113.2  -o StrictHostKeyChecking=no "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Create `~/.ssh/config` on Windows for the jump-host setup:

```powershell
@"
Host attacker
    HostName 203.0.113.50
    User maverick
    IdentityFile ~/.ssh/mtd_lab_key
    StrictHostKeyChecking no

Host sensor
    HostName 203.0.113.2
    User maverick
    IdentityFile ~/.ssh/mtd_lab_key
    StrictHostKeyChecking no

Host server
    HostName 172.16.10.10
    User maverick
    IdentityFile ~/.ssh/mtd_lab_key
    StrictHostKeyChecking no
    ProxyJump sensor

Host honeypot
    HostName 172.16.10.20
    User maverick
    IdentityFile ~/.ssh/mtd_lab_key
    StrictHostKeyChecking no
    ProxyJump sensor
"@ | Set-Content "$HOME\.ssh\config" -Encoding ASCII
```

Push to server + honeypot (via sensor jump):

```powershell
type $HOME\.ssh\mtd_lab_key.pub | ssh server   "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
type $HOME\.ssh\mtd_lab_key.pub | ssh honeypot "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Test all four:

```powershell
@("attacker","sensor","server","honeypot") | ForEach-Object {
    Write-Output "=== $_ ==="
    ssh $_ "hostname; whoami; sudo -n true && echo SUDO_OK"
}
```

All four should print `<vm-name>`, `maverick`, `SUDO_OK` with no password prompts.

## (Optional) Disable password auth on all 4 VMs

On each VM:

```bash
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
sudo systemctl reload ssh
```

## Snapshots

In VMware, on each VM: VM → Snapshot → Take Snapshot → name `pre-ansible`.

On the attacker, also take `clean-recon` **after Ansible provisions the attacker** (drops `run_attack.py`). Used to reset between Run A and Run B of the demo.

## Connectivity test matrix

| From | To | Expected |
|---|---|---|
| Windows host | 203.0.113.50 (attacker) | ping OK |
| Windows host | 203.0.113.2 (sensor WAN) | ping OK |
| Attacker | 203.0.113.2 (sensor WAN) | ping OK |
| Sensor | 172.16.10.10 (server) | ping OK |
| Sensor | 172.16.10.20 (honeypot) | ping OK |
| Server | 172.16.10.1 (sensor DMZ) | ping OK |
| Honeypot | 172.16.10.1 (sensor DMZ) | ping OK |
| Server | 172.16.10.20 (honeypot) | ping OK (same segment) |
| Attacker | 172.16.10.10 (server) | **fails until sensor DNAT is in place** — expected |

## What gets installed by Ansible (per VM)

| VM | Ansible role installs |
|---|---|
| Sensor | iptables rules (firewall + DNAT), Suricata (inline NFQUEUE), Python MTD controller, systemd service, FastAPI dashboard on port 43123 |
| Server | nginx (HTTP+HTTPS, all HTTPS ports in pool), self-signed cert, openssh-server on all SSH ports in pool |
| Honeypot | Cowrie (SSH medium-interaction), rsyslog forwarding to sensor |
| Attacker | nmap, hydra, sqlmap, curl, Python 3, `run_attack.py` deployed to `/opt/mtd-attacker/` |

See `docs/VM_SETUP.md` for the narrative version of each install (what each role does and why).
