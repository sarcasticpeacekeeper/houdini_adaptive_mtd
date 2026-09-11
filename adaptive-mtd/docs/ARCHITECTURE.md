# Adaptive MTD Lab — Architecture

## What this lab demonstrates

A **Moving Target Defense (MTD)** demo: the public-facing attack surface (IP + L4 port) rotates over time so attacker reconnaissance goes stale before it can be used. **Adaptive** MTD changes the rotation rate in response to threat telemetry — quiet network = slow rotation (low cost), active attack = fast rotation (high cost).

The single most important thing the demo shows: **legitimate users never notice the surface moving, while the attacker's map keeps expiring.**

## The two MTD features (only these)

1. **IP diversity** — the public-facing service IP rotates among a pool of virtual IPs configured on the DMZ server.
2. **Port diversity** — the public-facing L4 port of each service (SSH, HTTPS) rotates.

No kernel-level MTD, no ASLR, no application-layer mutation. Just these two network-layer features.

## Attacker redirection to the honeypot (redesign)

Layered on top of the rotation, there is a **per-source attacker redirect**:
once Suricata + the MTD controller decide a source IP is an attacker (a
high-severity Suricata alert from that source), the controller installs an
iptables rule that DNATs **that source's** HTTPS/SSH traffic to the
honeypot's dummy website, while legit clients keep going to the real
server. The redirect is sticky for the rest of the demo.

Mechanism — iptables PREROUTING is processed top-to-bottom, first match wins:

```
# (top, highest priority) per-source attacker rule
iptables -t nat -I PREROUTING 1 -i ens33 -s <attacker_ip> -p tcp --dport <https_port> -j DNAT --to 172.16.10.20:443
# (below, catches everyone else) general rotation rule
iptables -t nat -A PREROUTING -i ens33 -p tcp --dport <https_port> -j DNAT --to <current_server_vip>:443
```

So the attacker hits the honeypot's dummy website (thinks they're winning);
legit clients fall through to the real server (rotating VIP). When the
surface rotates, the controller rewrites BOTH the general rule AND all
per-source attacker rules to the new public port, so the redirect stays
valid.

The honeypot now runs **two** decoys: Cowrie (SSH) + nginx (dummy website).

## Network topology — 4 VMs, 3 segments

```
                        OUTSIDE (untrusted)
                              | WAN  203.0.113.0/24  (simulated "internet", no real egress)
                              |
                       +------v-------+
                       |  VM-1 Kali   |  Attacker  203.0.113.50
                       +--------------+
                              | WAN
                       +------v-------+
                       | VM-2 Sensor  |  Firewall + IDS/IPS + MTD controller
                       | Ubuntu, 3 NIC|  iptables + Suricata (NFQUEUE) + Python controller
                       +--+-------+---+
                          | DMZ   | LAN
              172.16.10.0/24     192.168.10.0/24
                |                        |
        +-------+-------+                |
   +----v----+  +-----v---+              (LAN segment reserved for future
   |VM-3 Srv |  |VM-4 Honey|              Client VM — not built in this
   |.10      |  |.20       |              4-VM scope)
   |nginx+ssh|  |Cowrie    |
   +---------+  +----------+
```

### VM roles and FOSS stack

| VM | Name | OS | Role | FOSS stack |
|---|---|---|---|---|
| 1 | Attacker | Kali Linux 2026 | External threat actor; fixed small attack set | nmap, hydra, sqlmap, curl, Python |
| 2 | **Sensor** | Ubuntu 24.04 Server + XFCE | Perimeter firewall + IDS/IPS **+ the MTD controller (the brain)** + lightweight GUI for demo viewing | iptables, Suricata (inline NFQUEUE), Python MTD controller, FastAPI dashboard, XFCE + Firefox |
| 3 | Server | Ubuntu 24.04 Server | Defended target; passive — configured once with a pool of VIPs and listening ports, then left alone | nginx (HTTP/HTTPS), openssh-server |
| 4 | Honeypot | Ubuntu 24.04 Server | SSH decoy + dummy website that lures the attacker and trips MTD | Cowrie (SSH, medium-interaction), nginx (dummy website), syslog to sensor |

> **Future:** a 5th VM (SIEM running Wazuh single-node) and a 6th VM (Client demo prop) are out of scope for this build. The controller has a stubbed Wazuh input; the client loop can be run from the Windows host during the demo.

### Static IP plan

| VM | NIC / IP |
|---|---|
| Attacker | eth0: 203.0.113.50/24, gw 203.0.113.1 |
| Sensor | ens33: 203.0.113.2/24 (WAN), ens37: 172.16.10.1/24 (DMZ), ens38: 192.168.10.1/24 (LAN) |
| Server | ens33: 172.16.10.10/24, gw 172.16.10.1 |
| Honeypot | ens33: 172.16.10.20/24, gw 172.16.10.1 |

The Sensor is the default gateway for DMZ (and LAN, if/when used). IP forwarding enabled on the Sensor. WAN has no real upstream; sensor default route → `203.0.113.1` (the Windows host adapter on VMnet2), egress dropped in iptables.

## Where the MTD logic lives — on the Sensor

The **MTD controller runs on the Sensor VM**, not the Server. Deliberate:

- The brain is **not** on the defended asset — if the server falls, the defender doesn't.
- Suricata runs on the sensor → controller reads EVE JSON **locally** (no hop).
- iptables runs on the sensor → controller updates NAT rules **locally**.
- **IP rotation = change the DNAT target** on the sensor. Server has all VIPs configured at install time; no per-rotation server action.
- **Port rotation = change the public-port → internal-port DNAT map** on the sensor. Server runs services on a fixed pool of ports.

The server is intentionally passive and "dumb" — it hosts services on a pool of IPs and ports; the sensor picks which is publicly reachable.

### Adaptive policy (the "adaptive" part)

`threat_level` in `[0..10]`:

- **Baseline**: `T_base = 60s`.
- **Honeypot event** (Cowrie): `threat_level += 2`, capped 10.
- **Suricata alert** (IDS): `+1` per alert, `+3` high-severity.
- **Wazuh correlation** (optional, stubbed in this build): `+1`.
- **Decay**: `threat_level *= 0.9` each tick.
- **Effective period**: `T_eff = T_base / (1 + threat_level)`.

Quiet network → 60s; active attack → ~5s. Shown live on the dashboard.

### Controller inputs / outputs

Inputs (read on the sensor):
- Suricata EVE JSON — tail `/var/log/suricata/eve.json`.
- Cowrie events — honeypot ships syslog to sensor (or SSH-tail cowrie JSON).
- Wazuh alerts — optional, stubbed.

Outputs (applied on the sensor):
- `iptables -t nat -D/... ; -A DNAT ...` to point public DNAT at new VIP/port.
- Old VIP/port goes dark from WAN instantly.
- Rotation event → local JSON log (`/var/log/mtd/rotations.json`).

The controller exposes a **`mtd_enabled` toggle** (config + dashboard button) for the A/B comparison.

## Config pools

- **VIP pool** (DMZ IPs the server answers on): `172.16.10.10`–`.14`
- **SSH public port pool** (→ internal 22): `22`, `2222`, `22022`, `20222`, `22002`
- **HTTPS public port pool** (→ internal 443): `443`, `8443`, `4443`, `8444`, `4444`
- `T_base = 60s`, decay `0.9`, honeypot bump `+2`, IDS bump `+1` / `+3` high.

Server is configured at install time to listen on **all** VIPs (`ip addr add` each) and **all** ports (nginx `listen` for each HTTPS port; sshd on multiple ports). Sensor iptables picks one VIP + one port to expose publicly and rotates among them.

## The demo — A/B "with vs without MTD"

Run the **same** `attacker/run_attack.py` twice; only `mtd_enabled` differs. Reset attacker to clean snapshot between runs (no saved recon).

### Run A — MTD OFF (failure case)
- Dashboard: `mtd_enabled = OFF`, VIP/ports frozen.
- Full chain: scan → brute force → web exploit → ssh login — all succeed.
- Punchline: "Static surface. One scan, full compromise. This is what we fix."

### Run B — MTD ON (defended case)
- Flip `mtd_enabled = ON` live. Reset attacker to clean snapshot.
- Run the **same** `attacker/run_attack.py`.
- First scan works but stale in seconds; brute force hits dead ports/honeypot; web exploit 404s on rotated port; SSH login lands on old VIP → dropped.
- Punchline: "Same attacker, same script, same tools. Only difference: the surface moves. That's MTD."

### Side-by-side comparison on the dashboard

| Metric (same attack script) | Run A — MTD OFF | Run B — MTD ON |
|---|---|---|
| Successful port scans | 1 | 1 (but stale) |
| Brute-force attempts hitting real server | high | 0 (honeypot/dead) |
| Web exploit requests reaching the app | high | ~0 |
| SSH sessions on real server | 1+ | 0 |
| Times attacker had to re-scan | 0 | many |
| Service uptime seen by legit client | 100% | 100% |

## MITRE ATT&CK mapping (the limited attack set)

| Phase | ATT&CK ID | Technique | Detected by | MTD response |
|---|---|---|---|---|
| 1 | T1046 | Network Service Scanning | Suricata (port-scan sig) | Port rotation invalidates scan |
| 2 | T1110 | Brute Force | Cowrie + Suricata | Honeypot trip → rate up + IP rotation |
| 3 | T1190 | Exploit Public-Facing App | Suricata (web-attack sig) | Port rotation breaks delivery |
| 4 | T1078 | Valid Accounts (attempted) | Cowrie (failed login) | Old VIP unreachable via sensor |
| — | T1592 | Gather Victim Host Info | Suricata (recon) | Recon goes stale |

Attacker runs only these, in this order, via one `attacker/run_attack.py` with `--phase` flags. See `docs/MITRE_MAPPING.md` for exact Suricata SIDs and Cowrie event types.
