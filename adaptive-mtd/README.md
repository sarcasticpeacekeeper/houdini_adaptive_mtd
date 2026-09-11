# Adaptive MTD Lab

A **Moving Target Defense (MTD)** demonstration lab built with FOSS tools. The public-facing attack surface (IP + L4 port) rotates over time so attacker reconnaissance goes stale before it can be used. **Adaptive** MTD changes the rotation rate in response to threat telemetry — quiet network = slow rotation (low cost), active attack = fast rotation (high cost).

The single most important thing the demo shows: **legitimate users never notice the surface moving, while the attacker's map keeps expiring.**

## What's in the lab

- **4 VMs** on VMware Workstation Pro (Windows host), 3 isolated network segments.
- **MTD controller** runs on the Sensor VM (the brain is not on the defended asset).
- **Two MTD features only**: IP diversity + port diversity, both done as iptables DNAT changes on the sensor.
- **Adaptive policy**: `T_eff = T_base / (1 + threat_level)` — quiet → 60s, active attack → ~5s.
- **A/B demo**: same attack script twice, only `mtd_enabled` differs.
- **Limited attack set** mapped to MITRE ATT&CK (T1046, T1110, T1190, T1078, T1592).

## Topology

```
                        OUTSIDE (untrusted)
                              | WAN  203.0.113.0/24
                              |
                       +------v-------+
                       |  VM-1 Kali   |  Attacker  203.0.113.50
                       +--------------+
                              |
                       +------v-------+
                       | VM-2 Sensor  |  Firewall + IDS/IPS + MTD controller
                       | Ubuntu, 3 NIC|  iptables + Suricata (NFQUEUE) + Python
                       +--+-------+---+
                          | DMZ   | LAN
              172.16.10.0/24     192.168.10.0/24
                |
        +-------+-------+
   +----v----+  +-----v---+
   |VM-3 Srv |  |VM-4 Honey|
   |.10      |  |.20       |
   |nginx+ssh|  |Cowrie    |
   +---------+  +----------+
```

| VM | Role | OS | RAM |
|---|---|---|---|
| 1 | Attacker | Kali 2026 | 3 GB |
| 2 | Sensor (the brain) | Ubuntu 24.04 Server + XFCE | 2.5 GB |
| 3 | Server (passive target) | Ubuntu 24.04 Server | 1 GB |
| 4 | Honeypot (Cowrie) | Ubuntu 24.04 Server | 1 GB |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## Repo layout

```
adaptive-mtd/
├── docs/
│   ├── ARCHITECTURE.md       # 4-VM topology, controller on sensor
│   ├── VMWARE_SETUP.md       # per-VM VMware + OS install guide
│   ├── VM_SETUP.md           # narrative: what each Ansible role installs
│   ├── DEMO_SCRIPT.md        # A/B demo flow, timed, with narration
│   └── MITRE_MAPPING.md      # MITRE table + Suricata SIDs + Cowrie events
├── ansible/
│   ├── inventory.yml        # 4 VMs + IPs + jump host config
│   ├── site.yml             # runs all roles
│   ├── group_vars/all.yml   # VIP pool, port pool, timing, paths
│   └── roles/
│       ├── sensor/          # iptables + Suricata + controller + dashboard
│       ├── server/          # nginx + sshd on the full pool
│       ├── honeypot/        # Cowrie + rsyslog to sensor
│       └── attacker/        # nmap/hydra/sqlmap + run_attack.py
├── mtd_controller/          # Python MTD controller (runs on sensor)
│   ├── config.py            # pools, timing, mtd_enabled toggle
│   ├── state.py             # current surface + rotation history
│   ├── policy.py            # threat_level state machine, T_eff, decay
│   ├── suricata_reader.py   # tails /var/log/suricata/eve.json
│   ├── cowrie_reader.py     # tails /var/log/cowrie/cowrie.json
│   ├── rotator.py           # applies iptables NAT changes
│   └── controller.py        # main loop: events -> policy -> maybe rotate
├── dashboard/               # FastAPI + Jinja2 dashboard (port 43123)
│   ├── main.py
│   └── templates/index.html
├── attacker/
│   └── run_attack.py        # --phase {scan,brute,web,ssh,all}, MITRE-tagged
├── requirements.txt
└── README.md
```

## Quick start

### 1. Build the VMs (manual, ~30 min)

Follow [`docs/VMWARE_SETUP.md`](docs/VMWARE_SETUP.md). Summary:

1. Download Kali 2026 (amd64) + Ubuntu 24.04 LTS Server (amd64) ISOs.
2. In VMware Virtual Network Editor, create 3 host-only VMnets:
   - VMnet2 = `203.0.113.0/24` (WAN, host adapter ON)
   - VMnet3 = `172.16.10.0/24` (DMZ, host adapter OFF)
   - VMnet4 = `192.168.10.0/24` (LAN, host adapter OFF)
3. Set the Windows VMnet2 adapter IP to `203.0.113.1/24`.
4. Open Windows firewall for ICMP + SSH (commands in the setup doc).
5. **Disable Cloudflare WARP** (it breaks host→VM traffic on VMware host-only networks).
6. Create 4 VMs per the spec table, install the OS, set static IPs via netplan/nmcli.
7. On each VM: create the `maverick` user with passwordless sudo, enable SSH.
8. From Windows: generate an SSH key, push to all 4 VMs (sensor as jump host for DMZ).
9. Snapshot each VM as `pre-ansible`.

### 2. Provision everything (one command, ~10 min)

From the Windows host (PowerShell), in this repo:

```powershell
# install ansible on Windows (one-time)
pip install ansible

# provision all 4 VMs
ansible-playbook -i ansible/inventory.yml ansible/site.yml
```

This installs: iptables + Suricata + the Python controller + the FastAPI dashboard on the sensor; nginx + sshd on the full pool on the server; Cowrie on the honeypot; the attack tools + `run_attack.py` on the attacker.

### 3. Take the post-ansible snapshot on the attacker

In VMware, snapshot the attacker VM as `clean-recon`. You'll revert to this between Run A and Run B of the demo.

### 4. Open the dashboard

The demo is **fully self-contained** — no Windows host browser needed. On the sensor's XFCE desktop, open Firefox to:

```
https://localhost:43123
```

(Self-signed cert — accept the warning.) You should see the live dashboard with `mtd_enabled = OFF`. The legit client loop also runs in a terminal on the sensor (`bash /opt/mtd-client/follow-surface.sh`), so the green stream is visible on the sensor's console next to the dashboard.

### 5. Run the demo

Follow [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md). Summary:

**Run A — MTD OFF:**
```bash
ssh attacker
python3 /opt/mtd-attacker/run_attack.py --phase all
```
Full compromise in under a minute.

**Reset:** revert attacker to `clean-recon` snapshot, click **Enable MTD** on the dashboard.

**Run B — MTD ON:**
```bash
ssh attacker
python3 /opt/mtd-attacker/run_attack.py --phase all
```
Same script — every phase fails because the surface rotated.

## The adaptive policy

`threat_level` in `[0..10]`:

| Event | Bump |
|---|---|
| Cowrie (honeypot) event | +2 |
| Suricata alert, severity high | +3 |
| Suricata alert, severity medium | +1 |
| Suricata alert, severity low | +1 |
| Wazuh correlation (stubbed) | +1 |
| Decay each tick | `*= 0.9` |

`T_eff = T_base / (1 + threat_level)` — quiet → 60s, active attack → ~5s. Shown live on the dashboard.

## FOSS stack

| Component | Tool |
|---|---|
| Firewall | iptables |
| IDS/IPS | Suricata (inline NFQUEUE) |
| Honeypot | Cowrie |
| Web service | nginx |
| SSH service | openssh-server |
| MTD controller | Python 3 |
| Dashboard | FastAPI + uvicorn + Jinja2 |
| Provisioning | Ansible |
| Attacker tools | nmap, hydra, sqlmap, curl |

No proprietary software. No paid services.

## What's NOT in this build (future work)

- **Wazuh SIEM** — the controller has a stubbed Wazuh input. Add a 5th VM running Wazuh single-node, ship logs to it.
- **Client VM** — the legit-user `curl` loop can run from the Windows host during the demo. Add a 6th VM for a self-contained demo.
- **Kernel-level MTD, ASLR, app mutation** — explicitly out of scope.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ansible-playbook` can't reach a VM | Check SSH key + jump host config in `~/.ssh/config` |
| Dashboard not loading | `sudo systemctl status mtd-dashboard` on the sensor |
| Rotations not happening | Check `mtd_enabled` is ON; `sudo systemctl status mtd-controller` |
| Windows can't ping VMs | Disable Cloudflare WARP; check VMnet2 host adapter IP |
| Suricata not alerting | `sudo systemctl status suricata`; check `/var/log/suricata/eve.json` is growing |
| Cowrie not logging | `sudo systemctl status cowrie` on honeypot; check rsyslog both ends |

See [`docs/VMWARE_SETUP.md`](docs/VMWARE_SETUP.md) for the full setup troubleshooting guide.

## License

FOSS for educational use. See individual upstream licenses for Suricata, Cowrie, nginx, etc.
