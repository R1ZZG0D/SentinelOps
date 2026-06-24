# Architecture

SentinelOps models the data flow of a modern MDR/XDR SOC. Each stage maps to a directory in this repo so the project is auditable end to end.

## Data flow

```
1. TELEMETRY GENERATION
   Atomic Red Team / Caldera execute MITRE ATT&CK techniques on lab endpoints.
   Endpoints emit:
     - Windows Security Event Logs (4624/4625/4688/4720/7045 ...)
     - Linux auditd / syslog (execve, sudo, sshd ...)
     - Network logs (Zeek conn.log, Suricata EVE alerts)

2. INGESTION & NORMALIZATION   →  ingestion/parsers/
   Raw, source-specific text is parsed with regex and mapped to ONE schema
   (an Elastic Common Schema-style subset). This is what makes cross-source
   correlation possible: a "source IP" means the same field whether it came
   from Windows, auditd, or Zeek.

3. DETECTION                   →  detections/sigma/ + docker/ (Wazuh)
   Sigma rules express detection logic in a backend-agnostic YAML format.
   CI converts/validates them; Wazuh evaluates incoming events against rules
   and raises alerts. Each rule carries a MITRE ATT&CK technique tag.

4. CI/CD FOR DETECTIONS        →  .github/workflows/detections-ci.yml
   Every change to a rule is linted, schema-validated, and (on merge) deployed.
   This mirrors how an MDR provider ships detection content to a fleet safely:
   no hand-editing rules in production.

5. TRIAGE & INVESTIGATION      →  triage-assistant/
   When an alert fires, the AI assistant:
     a. enriches it (GeoIP, asset criticality, threat-intel reputation)
     b. correlates related events into a single incident narrative
     c. assigns severity using a transparent scoring model
     d. writes a Tier-3-style investigation summary + customer recommendations

6. RESPONSE                    →  runbooks/
   Each high-value detection has an IR runbook: triage questions, containment,
   eradication, recovery, and the data needed to decide true/false positive.
```

## Why Wazuh

Wazuh is an open-source SIEM + XDR that bundles log analysis, an agent-based
EDR, file-integrity monitoring, and built-in MITRE ATT&CK mapping in a single
free, Docker-deployable stack. That makes it the closest open analog to a
commercial GreyMatter/XDR platform and the lightest option for a constrained
home lab (single-node ≈ 3-4 GB disk).

The stack has three services:

| Service | Role |
|---------|------|
| `wazuh.manager` | Rule engine, decoders, alerting, agent management. |
| `wazuh.indexer` | OpenSearch-based storage + search backend for events/alerts. |
| `wazuh.dashboard` | Kibana-style UI for hunting, dashboards, and alert review. |

## Normalized schema (ECS subset)

All parsers emit events shaped like:

```json
{
  "@timestamp": "2026-06-24T14:03:11Z",
  "event": { "category": "authentication", "action": "logon_failed", "outcome": "failure" },
  "source": { "ip": "203.0.113.7", "port": 51514 },
  "destination": { "ip": "10.0.0.5", "port": 22 },
  "user": { "name": "root" },
  "host": { "name": "web01", "os": "linux" },
  "log": { "source": "linux_auditd" },
  "raw": "…original line…"
}
```

Keeping `raw` lets an analyst always fall back to ground truth; the structured
fields are what detections and correlation run on.
