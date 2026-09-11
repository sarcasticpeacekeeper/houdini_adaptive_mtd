# MITRE ATT&CK Mapping

The attacker runs a fixed, limited set of techniques in a fixed order via one script (`attacker/run_attack.py --phase {scan,brute,web,ssh,all}`). No free-form hacking. Each technique maps to a Suricata signature or Cowrie event that the MTD controller reads to bump `threat_level`.

## Attack phases

| Phase | ATT&CK ID | Technique | Tool | Detected by | MTD response |
|---|---|---|---|---|---|
| 1 | T1046 | Network Service Scanning | `nmap -sS -p- 203.0.113.2` | Suricata port-scan signature | Port rotation invalidates the scan map |
| 2 | T1110 | Brute Force | `hydra -L users.txt -P pass.txt -s <ssh_port> ssh://203.0.113.2` | Cowrie (if redirected) + Suricata brute-force sig | Honeypot trip → rate up + IP rotation |
| 3 | T1190 | Exploit Public-Facing Application | `sqlmap -u https://203.0.113.2:<https_port>/ --batch` | Suricata web-attack signature | Port rotation breaks delivery |
| 4 | T1078 | Valid Accounts (attempted) | `ssh -p <ssh_port> maverick@203.0.113.2` | Cowrie failed-login (if redirected) | Old VIP unreachable via sensor DNAT |
| (recon) | T1592 | Gather Victim Host Info | `nmap -sV 203.0.113.2` | Suricata recon signature | Recon goes stale on next rotation |

## Suricata custom rules (lab SIDs)

These are added to `/etc/suricata/rules/mtd.rules` on the sensor. SIDs are in the `9000000` range (local) to avoid collisions with ET/Open.

### T1046 — Network Service Scanning

```
alert tcp $HOME_NET any -> $HOME_NET any (msg:"MTD-LAB T1046 port scan detected (nmap)"; flags:S,12; ttl:40-60; detection_filter:track by_src, count 30, seconds 10; sid:9000001; rev:1; classtype:attempted-recon; priority:2;)
```

Triggers when a single source sends ≥30 SYN packets in 10 seconds. Severity: medium → `+1` to threat_level.

### T1110 — Brute Force

```
alert tcp $HOME_NET any -> $HOME_NET 22 (msg:"MTD-LAB T1110 SSH brute force"; flow:to_server; flags:S; detection_filter:track by_src, count 20, seconds 30; sid:9000002; rev:1; classtype:attempted-admin; priority:1;)
```

Triggers when a single source sends ≥20 SSH SYN in 30 seconds. Severity: high → `+3` to threat_level.

### T1190 — Exploit Public-Facing Application

```
alert http $HOME_NET any -> $HOME_NET any (msg:"MTD-LAB T1190 sqlmap user-agent detected"; flow:to_server; http_user_agent; content:"sqlmap"; nocase; sid:9000003; rev:1; classtype:web-application-attack; priority:1;)
```

Triggers on the `sqlmap/1.x` User-Agent string. Severity: high → `+3` to threat_level.

```
alert http $HOME_NET any -> $HOME_NET any (msg:"MTD-LAB T1190 SQLi probe pattern"; flow:to_server; http_uri; content:"'"; pcre:"/(\bunion\b|\bselect\b|\bor\b).*'/Ui"; sid:9000004; rev:1; classtype:web-application-attack; priority:1;)
```

Triggers on classic SQLi patterns in the URI. Severity: high → `+3`.

### T1592 — Gather Victim Host Info

```
alert tcp $HOME_NET any -> $HOME_NET any (msg:"MTD-LAB T1592 service version probe (nmap -sV)"; flags:S,12; ttl:40-60; dsize:0; detection_filter:track by_src, count 10, seconds 5; sid:9000005; rev:1; classtype:attempted-recon; priority:2;)
```

Triggers on small null-payload SYN bursts characteristic of `-sV`. Severity: medium → `+1`.

## Suricata severity → threat_level bump mapping

The controller's `suricata_reader.py` reads EVE JSON and maps severity to a bump:

| Suricata severity (numeric, lower = worse) | classtype category | threat_level bump |
|---|---|---|
| `1` (high) | `web-application-attack`, `attempted-admin` | `+3` |
| `2` (medium) | `attempted-recon` | `+1` |
| `3` (low) | everything else | `+1` |

## Cowrie event types → threat_level bump

Cowrie logs JSON to `/var/log/cowrie/cowrie.json` (rsyslog-shipped to the sensor). The controller's `cowrie_reader.py` reads each event and maps the `eventid` field to a bump:

| Cowrie eventid | Meaning | threat_level bump |
|---|---|---|
| `cowrie.login.failed` | Failed SSH login attempt | `+1` |
| `cowrie.login.success` | Successful SSH login to the honeypot | `+2` (attacker got in — even though it's a decoy) |
| `cowrie.command.input` | Attacker ran a command in the honeypot | `+2` |
| `cowrie.session.connect` | New SSH session started | `+1` |

All bumps are capped so `threat_level` never exceeds `10`.

## Wazuh correlation (optional, stubbed)

The controller has a stubbed `wazuh_reader.py` that returns no events (`wazuh_enabled: false` in config). When a Wazuh single-node is added later, it will:
- Read Wazuh alerts via the Wazuh API (`/var/ossec/framework/python/tf/...`).
- Map Wazuh rule levels ≥7 to a `+1` bump.
- Correlate Suricata + Cowrie + Wazuh events into a single timeline.

For this build, the controller only reads Suricata + Cowrie. The Wazuh input is a no-op.

## Full event → bump → T_eff example

A quiet network:
- threat_level = 0
- T_eff = 60 / (1 + 0) = 60s

Attacker runs `nmap -sS -p-`:
- Suricata fires SID 9000001 (T1046 port scan, severity 2) → `+1`
- threat_level = 1
- T_eff = 60 / (1 + 1) = 30s

Attacker runs `hydra`:
- Suricata fires SID 9000002 (T1110 brute force, severity 1) → `+3`
- Cowrie fires `cowrie.login.failed` × many → `+1` each, but capped
- threat_level = 1 + 3 = 4 (then decays 0.9 each tick)
- T_eff = 60 / (1 + 4) = 12s

Attacker runs `sqlmap`:
- Suricata fires SID 9000003 (T1190 sqlmap UA, severity 1) → `+3`
- threat_level = 4 + 3 = 7 (capped at 10)
- T_eff = 60 / (1 + 7) = 7.5s

Attacker stops:
- threat_level *= 0.9 each tick
- After ~20 ticks (one tick = T_eff seconds), threat_level ≈ 0.9^20 × 7 ≈ 0.8
- T_eff climbs back toward 60s

This is the "adaptive" behavior the dashboard shows live.
