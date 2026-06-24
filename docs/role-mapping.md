# Role mapping — SOC / MDR detection-engineering role

This file maps common requirements for a SOC / GreyMatter-style MDR analyst role
to concrete artifacts in this repository, so the project can be cited directly on
a résumé and walked through in an interview.

| Job requirement / keyword | Demonstrated by | Talk-track for the interview |
|---|---|---|
| SIEM operations (Splunk / ELK class) | `docker/` Wazuh stack | "I stood up a single-node Wazuh SIEM in Docker — manager, indexer, dashboard — and used it as the detection and hunting backend." |
| Log source integration & data ingestion | `ingestion/parsers/` | "I integrated Windows, Linux auditd, and Zeek network logs and wrote custom parsers to onboard each source." |
| Log formats / parsing / regex | `ingestion/parsers/*.py`, `ingestion/tests/` | "Each parser uses regex to extract fields and normalize three different log formats into one ECS-style schema, with unit tests gating changes." |
| Detection rule development & tuning | `detections/sigma/` | "I authored Sigma rules per technique, and tuned them against simulated attacks to cut false positives — documented in each runbook." |
| Detection-as-code / CI/CD | `.github/workflows/detections-ci.yml` | "Detections live in Git. A GitHub Actions pipeline lints and schema-validates every rule on PR and deploys on merge — same way an MDR ships content to a fleet." |
| Threat hunting | `detections/mitre_coverage.md`, `attack-simulation/` | "I built an ATT&CK coverage matrix and hunted for the gaps the simulated attacks exposed." |
| MITRE ATT&CK / Cyber Kill Chain | technique tags on every rule + `attack-simulation/atomic-catalog.md` | "Every detection is tagged with its ATT&CK technique and kill-chain phase, and mapped to the Atomic Red Team test that exercises it." |
| Alert triage & false-positive fine-tuning | `triage-assistant/`, runbook 'tuning' sections | "I built a triage assistant that scores alerts and flags likely false positives, and I documented tuning decisions per detection." |
| Tier 2/3 investigations / analysis methodology | `triage-assistant/triage.py`, `runbooks/` | "The assistant produces a Tier-3-style investigation: enrichment, correlation, a severity rationale, and next steps." |
| Incident response | `runbooks/` | "Each top detection has an IR runbook covering triage, containment, eradication, recovery." |
| Advisory / customer reporting | `triage-assistant/` report output | "The tool generates a customer-facing summary in plain language with prioritized recommendations — the deliverable an MDR analyst sends a client." |
| Network analysis / TCP-IP | `ingestion/parsers/zeek_conn.py`, network Sigma rules | "I parse Zeek conn.log, normalize the 5-tuple, and detect on network behavior like beaconing and port scans." |
| Automation / scripting (Python) | entire `ingestion/` and `triage-assistant/` | "The pipeline is Python end to end and runs in CI without external services." |
| AI applied to security operations | `triage-assistant/triage.py` | "I used an LLM to compress Tier-1 toil — enrichment and first-draft investigation write-ups — with a transparent, auditable scoring model behind it." |

## Suggested résumé bullet points

- Built **SentinelOps**, an end-to-end SOC detection lab: ingested Windows/Linux/network telemetry into a Wazuh SIEM via custom Python parsers (regex normalization to an ECS-style schema, unit-tested).
- Implemented **detection-as-code**: authored Sigma rules mapped to MITRE ATT&CK and shipped them through a GitHub Actions CI/CD pipeline that lint/validates and deploys detection content.
- Simulated adversary behavior with **Atomic Red Team**, mapped each test to its expected detection, and tuned rules to reduce false positives.
- Developed an **LLM triage assistant** that enriches and correlates alerts, scores severity, and auto-generates Tier-3 investigation summaries and customer-facing recommendations.
