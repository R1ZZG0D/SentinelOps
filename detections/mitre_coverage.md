# MITRE ATT&CK coverage matrix

Coverage provided by the SentinelOps detection content, mapped to the Cyber Kill
Chain and the Atomic Red Team tests that exercise each technique. This is the
artifact used for **threat-hunting gap analysis**: empty cells are where the lab
has telemetry but no detection yet.

| Kill-chain phase | Tactic | Technique | Detection | Atomic test |
|---|---|---|---|---|
| Reconnaissance | Discovery | T1046 Network Service Discovery | `net_port_scan.yml` | nmap sweep (`T1046`) |
| Delivery / Exploitation | Credential Access | T1110 Brute Force | `win_failed_logon_bruteforce.yml` | `T1110.001` |
| Delivery / Exploitation | Credential Access | T1110.001 Password Guessing (SSH) | `lnx_ssh_bruteforce.yml` | hydra SSH (`T1110.001`) |
| Installation | Execution | T1059.004 Unix Shell | `lnx_sudo_remote_payload.yml` | `T1059.004` |
| Installation | Command & Control | T1105 Ingress Tool Transfer | `lnx_sudo_remote_payload.yml` | `T1105` |
| Installation | Persistence | T1543.003 Windows Service | `win_service_install.yml` | `T1543.003` |
| Installation | Persistence | T1136.001 Create Local Account | `win_new_admin_account.yml` | `T1136.001` |
| Actions on Objectives | Privilege Escalation | T1098 Account Manipulation | `win_new_admin_account.yml` | `T1098` |
| Command & Control | Command & Control | T1071 Application Layer Protocol | `net_c2_beacon.yml` | `T1071.001` |
| Command & Control | Command & Control | T1571 Non-Standard Port | `net_c2_beacon.yml` | `T1571` |

## Coverage summary

- **Tactics covered:** Reconnaissance/Discovery, Credential Access, Execution,
  Persistence, Privilege Escalation, Command & Control.
- **Known gaps (next detections to build):** Defense Evasion (e.g. log clearing,
  T1070), Lateral Movement (T1021 remote services), Exfiltration (T1041). These
  are the deliberate hunting targets documented for the next iteration.

## How this maps to an incident

The included sample telemetry tells one story end to end — the same incident the
triage assistant investigates:

```
T1046  port scan from 203.0.113.7  ──▶  T1110.001  SSH brute force  ──▶
successful root login  ──▶  T1105/T1059.004  pull + run /tmp/x.sh  ──▶
T1571  beacon to 203.0.113.7:4444
```
