# Attacker VM — Manual Setup Walkthrough (Kali 2026.2)

The attacker is the simplest VM: Kali ships with nmap/hydra/sqlmap/curl preinstalled. We just verify the tools, deploy `run_attack.py` + wordlists, then switch to the host-only WAN.

Assumes: Kali 2026.2 installed, `kali`/`kali` user (or your install user) with sudo, working in the VMware console (no SSH needed).

## Phase 1 — base setup (VM on NAT for internet)

### 1.1 Verify internet + set hostname

```bash
ip -br a          # should show a NIC with a DHCP IP
ping -c 2 8.8.8.8
sudo apt update

sudo hostnamectl set-hostname attacker
sudo nano /etc/hosts
# ensure:
# 127.0.0.1 localhost
# 127.0.1.1 attacker
# ::1       localhost ip6-localhost ip6-loopback
```

### 1.2 Verify / install the attack tools

```bash
nmap --version | head -1
hydra -h 2>&1 | head -1
sqlmap --version
curl --version | head -1
python3 --version
```

If any are missing:

```bash
sudo apt install -y nmap hydra sqlmap curl python3
```

### 1.3 Snapshot

VMware: snapshot `attacker-phase1-done`.

## Phase 2 — deploy run_attack.py + wordlists (VM still on NAT)

### 2.1 Create the deploy directory

```bash
sudo mkdir -p /opt/mtd-attacker
```

### 2.2 Deploy run_attack.py

The script is in the repo at `attacker/run_attack.py`. Get it onto the attacker via shared folder, scp, or copy-paste.

If using a VMware shared folder (map `D:\JSACWC\Project\Cursor\adaptive-mtd` as `repo`):

```bash
sudo mkdir -p /mnt/repo
sudo mount -t fuse.vmhgfs-fuse .host:/repo /mnt/repo 2>/dev/null || sudo mount -t fuse.vmhgfs-fuse .host:/repo /mnt/repo
sudo cp /mnt/repo/attacker/run_attack.py /opt/mtd-attacker/run_attack.py
sudo chmod +x /opt/mtd-attacker/run_attack.py
```

If shared folder doesn't work, copy-paste the script content into a file:

```bash
sudo nano /opt/mtd-attacker/run_attack.py
# paste the contents of attacker/run_attack.py from the repo, save (Ctrl+O, Enter, Ctrl+X)
sudo chmod +x /opt/mtd-attacker/run_attack.py
```

### 2.3 Deploy the wordlists

```bash
sudo tee /opt/mtd-attacker/users.txt > /dev/null <<'EOF'
maverick
root
admin
ubuntu
user
test
EOF

sudo tee /opt/mtd-attacker/pass.txt > /dev/null <<'EOF'
maverick
password
123456
admin
root
letmein
welcome
changeme
EOF
```

### 2.4 Verify the script runs

```bash
python3 /opt/mtd-attacker/run_attack.py --phase scan --target 127.0.0.1
```

Should run an nmap scan against localhost and print MITRE-tagged output. `Ctrl+C` to stop early if you just want to confirm it runs.

### 2.5 Snapshot

VMware: snapshot `attacker-phase2-done`.

## Phase 3 — switch to host-only WAN

### 3.1 In VMware, set the NIC to host-only VMnet2

attacker VM -> Settings -> Network Adapter -> set to **Host-only: VMnet2** (WAN).

### 3.2 Boot, find the NIC name

```bash
ip -br a    # usually eth0 on Kali
```

### 3.3 Set the static IP via nmcli (Kali uses NetworkManager, not netplan)

```bash
nmcli con show    # find the connection name, e.g. "Wired connection 1"
sudo nmcli con mod "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses 203.0.113.50/24 \
  ipv4.gateway 203.0.113.1
sudo nmcli con up "Wired connection 1"
ip -br a
```

Should show `eth0 UP 203.0.113.50/24`.

### 3.4 Verify connectivity

From the **attacker**:

```bash
ping -c 2 203.0.113.1    # Windows host (if VMnet2 host adapter is on)
ping -c 2 203.0.113.2    # sensor WAN
```

From the **sensor**:

```bash
ping -c 2 203.0.113.50    # attacker
```

From **Windows PowerShell** (Cloudflare WARP off):

```powershell
ping 203.0.113.50
```

All should reply.

### 3.5 Snapshot

VMware: snapshot `attacker-provisioned`.

### 3.6 Take the clean-recon snapshot (for the A/B demo reset)

After everything is verified, take an extra snapshot named `clean-recon`. You'll revert the attacker to this between Run A (MTD off) and Run B (MTD on) of the demo so it starts with no saved scan data.

```bash
# confirm the current state is clean (no saved scan results)
ls -la /opt/mtd-attacker/scan_results.json 2>/dev/null && echo "scan cache exists - delete it before snapshot" || echo "clean - good to snapshot"
```

If `scan_results.json` exists, delete it:

```bash
rm -f /opt/mtd-attacker/scan_results.json
```

Then in VMware: snapshot `clean-recon`.

## Phase 3 checklist

| # | Done? | Step |
|---|---|---|
| 3.1 | ☐ | NIC set to host-only VMnet2 |
| 3.2 | ☐ | NIC name noted (eth0) |
| 3.3 | ☐ | Static IP set via nmcli, 203.0.113.50/24 |
| 3.4 | ☐ | Attacker <-> sensor + Windows ping works |
| 3.5 | ☐ | Snapshot `attacker-provisioned` |
| 3.6 | ☐ | Snapshot `clean-recon` taken (no scan_results.json) |

## What's on the attacker now

| Item | Location |
|---|---|
| nmap, hydra, sqlmap, curl, python3 | preinstalled on Kali |
| run_attack.py | /opt/mtd-attacker/run_attack.py |
| users.txt | /opt/mtd-attacker/users.txt |
| pass.txt | /opt/mtd-attacker/pass.txt |

## Running the attack (after all 4 VMs are provisioned)

```bash
# full attack chain
python3 /opt/mtd-attacker/run_attack.py --phase all --target 203.0.113.2

# single phase
python3 /opt/mtd-attacker/run_attack.py --phase scan --target 203.0.113.2
python3 /opt/mtd-attacker/run_attack.py --phase brute --target 203.0.113.2
python3 /opt/mtd-attacker/run_attack.py --phase web --target 203.0.113.2
python3 /opt/mtd-attacker/run_attack.py --phase ssh --target 203.0.113.2
```

The target is the sensor's WAN IP (203.0.113.2) — that's the public surface the sensor's DNAT exposes.
