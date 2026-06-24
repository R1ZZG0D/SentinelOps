# IR Runbook: SSH Brute Force → Account Compromise

- **Detection:** `detections/sigma/linux/lnx_ssh_bruteforce.yml`, Wazuh rule `100100` / `100101`
- **ATT&CK:** T1110.001 (Password Guessing), T1110 (Brute Force)
- **Severity:** high (critical if a success follows the burst)
- **Data sources:** Linux auth syslog (sshd), Zeek conn.log, threat-intel, asset CMDB

## 1. Triage questions
- Did a **successful** login (`logon`/`Accepted password`) follow the failures from
  the **same source IP**? (success-after-burst = escalate to critical)
- Is the source IP internal (scanner/automation) or external? What is its
  threat-intel verdict and geolocation?
- Which account(s) were targeted, and did any succeed? Was it a privileged account
  (`root`, `admin`, service accounts)?
- Is the target asset internet-facing and/or business-critical?
- How many failures, over what window, against how many usernames? (spray vs
  single-account brute force)

## 2. True vs false positive
| Likely TRUE positive if… | Likely FALSE positive if… |
|---|---|
| External source, many usernames, short window | Source is the internal vuln scanner / known automation |
| Threat-intel verdict is malicious | A single account after a recent password change (cached creds) |
| A success immediately follows the failures | Failures only, slow rate, one account, then user self-corrects |

## 3. Containment (evidence-preserving)
1. Block the source IP at the perimeter firewall / host firewall. **Do not** wipe
   the host — capture volatile state first if a success occurred.
2. If a login succeeded: isolate the host from the network (keep it powered on) and
   snapshot memory/disk for forensics.
3. Disable / force-logout the affected account(s); kill active SSH sessions from the
   source (`who`, `ss -tnp`, terminate matching PIDs).

## 4. Eradication
1. Confirm scope: did the attacker move laterally, create accounts, or install
   persistence? Check `last`, `/etc/passwd` diffs, new systemd units (rule `100110`),
   cron, authorized_keys, and Zeek for outbound C2 (`net_c2_beacon.yml`).
2. Reset credentials for every account exposed on the host; rotate any keys/secrets
   stored there.
3. Remove any attacker artifacts identified (payloads in `/tmp`, `/dev/shm`).

## 5. Recovery
1. Restore the account and host to service only after eradication is confirmed.
2. Harden: enforce key-based auth, disable password auth / root SSH, add fail2ban or
   rate-limiting, restrict SSH exposure to a bastion/VPN.
3. Add the source IP and any new IOCs to the blocklist; monitor the source/asset
   pair for recurrence.

## 6. Tuning notes
- 2026-06-24 — Internal vuln scanner (`10.0.0.30`) tripped the brute-force rule
  nightly → added it to an allowlist filter on `lnx_ssh_bruteforce` rather than
  raising the threshold (keeps detection sensitive for real attackers).
