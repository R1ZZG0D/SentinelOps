# IR Runbook: C2 Beaconing

- **Detection:** `detections/sigma/network/net_c2_beacon.yml`
- **ATT&CK:** T1071 (Application Layer Protocol), T1571 (Non-Standard Port)
- **Severity:** high
- **Data sources:** Zeek conn.log, firewall logs, EDR/process telemetry, threat-intel

## 1. Triage questions
- Which **internal host** is beaconing, and to which **external IP:port**? Is the
  destination known-bad (threat-intel)?
- Is the cadence regular (fixed interval ± jitter) and the payload small/consistent?
  Regular low-data flows to one external host = classic beacon.
- What process on the host owns the outbound connection? Is it expected software?
- Did this host appear in an earlier alert (e.g. SSH brute force, suspicious sudo)?
  Beaconing is usually post-exploitation — look upstream.

## 2. True vs false positive
| Likely TRUE positive if… | Likely FALSE positive if… |
|---|---|
| Destination is malicious / uncommon C2 port (4444, 1337…) | Internal app legitimately using that port to a known partner |
| Regular interval, low/consistent bytes, no business reason | Monitoring/telemetry agent with a documented endpoint |
| Owning process is a shell, script, or unsigned binary | Signed, expected software with a change-managed destination |

## 3. Containment (evidence-preserving)
1. Block the external C2 IP/port at the firewall (egress). Preserve the host —
   beaconing implies an active foothold; capture memory before remediation.
2. Network-isolate the beaconing host (keep powered on) to cut C2 while retaining
   forensic state.
3. Identify and suspend the owning process; preserve the binary/script for analysis.

## 4. Eradication
1. Determine the initial access vector (correlate with prior alerts on this host)
   and the persistence mechanism keeping the beacon alive.
2. Remove the implant and persistence (service, cron, systemd unit, startup item),
   and any dropped payloads.
3. Hunt for the same C2 IOC across the fleet — one beacon often means several.

## 5. Recovery
1. Rebuild or restore the host from a known-good image if implant scope is uncertain
   (preferred over in-place cleanup for confirmed C2).
2. Rotate credentials/secrets the host had access to.
3. Add the C2 IP, port, and any payload hashes to blocklists and detections; monitor
   for re-beaconing.

## 6. Tuning notes
- Consider adding a jitter/interval-analysis enrichment to cut false positives from
  bursty-but-benign apps before escalating (the triage assistant flags this).
