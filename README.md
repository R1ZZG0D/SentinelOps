# SentinelOps — AI-Augmented SOC Detection & Investigation Lab

> A home-lab SOC pipeline that pairs a real SIEM (Wazuh) with **detection-as-code**, **CI/CD-deployed detections**, MITRE ATT&CK-mapped **attack simulation**, and an **LLM-powered triage assistant** that enriches alerts and writes customer-style investigation summaries.

This project demonstrates the full SOC analyst loop — *ingest → detect → triage → investigate → report* — the way a modern MDR/XDR provider runs it, and adds an AI layer on top of it.

---

## Why this exists

Most SOC home labs stop at "I installed an SIEM and saw a login alert." This one treats detection content like software:

- **Detections are code** — authored as [Sigma](https://github.com/SigmaHQ/sigma) rules, version-controlled, validated and deployed by a **GitHub Actions CI/CD pipeline**.
- **Telemetry is normalized** — custom Python parsers turn raw Windows / Linux / network logs into a single ECS-style schema, with unit tests.
- **Attacks are reproducible** — Atomic Red Team tests are mapped to the detections they should trigger and to the MITRE ATT&CK techniques they exercise.
- **Investigation is augmented** — an LLM triage assistant enriches an alert, correlates evidence, assigns severity, and produces a Tier-3-style write-up + customer recommendations.

---

## Architecture

```
                    ATTACK SIMULATION                         DETECTION-AS-CODE
              (Atomic Red Team / Caldera)                   (Sigma rules in Git)
                          │                                          │
                          │ generates telemetry                      │ CI/CD: validate → convert → deploy
                          ▼                                          ▼
   ┌──────────────┐   ┌───────────────────────────────┐   ┌─────────────────────┐
   │ Windows logs │──▶│  ingestion/parsers (Python)    │──▶│      WAZUH SIEM      │
   │ Linux auditd │──▶│  regex normalize → ECS schema  │   │  manager + indexer  │
   │ Zeek/Suricata│──▶│  (unit-tested)                 │   │  + dashboard        │
   └──────────────┘   └───────────────────────────────┘   └──────────┬──────────┘
                                                                      │ alerts
                                                                      ▼
                                                       ┌──────────────────────────────┐
                                                       │   AI TRIAGE ASSISTANT (LLM)   │
                                                       │  enrich → correlate → score   │
                                                       │  → investigation summary +    │
                                                       │    customer recommendations   │
                                                       └──────────────────────────────┘
```

See [`docs/architecture.md`](docs/architecture.md) for the detailed data flow.

---

## Repository layout

| Path | What's in it |
|------|--------------|
| [`docker/`](docker/) | `docker compose` stack for a single-node Wazuh SIEM (manager + indexer + dashboard). |
| [`ingestion/`](ingestion/) | Custom log parsers (regex → normalized ECS schema) + unit tests + sample raw logs. |
| [`detections/`](detections/) | Sigma detection rules (Windows / Linux / network) + MITRE ATT&CK coverage matrix. |
| [`.github/workflows/`](.github/workflows/) | CI/CD pipeline: lint + validate Sigma, run parser tests, convert rules, deploy stub. |
| [`triage-assistant/`](triage-assistant/) | LLM triage tool — alert enrichment, correlation, scoring, investigation report. |
| [`attack-simulation/`](attack-simulation/) | Atomic Red Team test catalog mapped to detections + ATT&CK techniques. |
| [`runbooks/`](runbooks/) | Incident-response runbooks for the top detections. |
| [`docs/`](docs/) | Architecture, and an explicit mapping of this repo to a SOC job description. |

---

## Quick start

### 1. Run the SIEM (needs Docker + ~4 GB free disk)
```bash
cd docker
cp .env.example .env            # set credentials
./generate-certs.sh             # one-time TLS certs for the Wazuh stack
docker compose up -d
# Dashboard: https://localhost:443  (login from .env)
```

### 2. Parse + normalize logs (no dependencies, pure stdlib)
```bash
python3 -m ingestion.parsers.cli ingestion/sample_logs/linux_auditd.log --source linux_auditd
python3 -m pytest ingestion/tests -q          # run the parser unit tests
```

### 3. Triage an alert with the AI assistant
```bash
cd triage-assistant
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...            # optional — falls back to offline rules engine
python3 triage.py sample_alerts/ssh_bruteforce.json
```

### 4. Validate detections like the CI does
```bash
pip install sigma-cli
sigma check detections/sigma            # the same check GitHub Actions runs on every PR
```

---

## What each part demonstrates

| Capability | Where it lives |
|------------|----------------|
| SIEM operation (Splunk/ELK-class) | `docker/` — Wazuh manager + indexer + dashboard |
| Log source integration & data ingestion | `ingestion/parsers/` |
| Log formats, regex, normalization | `ingestion/parsers/*.py`, `ingestion/tests/` |
| Detection rule development & tuning | `detections/sigma/` |
| Detection-as-code CI/CD | `.github/workflows/detections-ci.yml` |
| Threat hunting & MITRE ATT&CK | `detections/mitre_coverage.md`, `attack-simulation/` |
| Alert triage & false-positive tuning | `triage-assistant/`, runbook tuning notes |
| Incident response | `runbooks/` |
| Advisory / customer reporting | `triage-assistant/` (generates customer-style summaries) |
| AI/automation differentiator | `triage-assistant/triage.py` |

A line-by-line mapping to the target role is in [`docs/role-mapping.md`](docs/role-mapping.md).

---

## Status

- [x] Repo + detection-as-code structure
- [x] Custom parsers + unit tests *(13/13 passing)*
- [x] Sigma detection rules + MITRE coverage matrix *(validated by `sigma check`)*
- [x] CI/CD pipeline *(green on GitHub Actions)*
- [x] AI triage assistant (online + offline modes)
- [x] IR runbooks
- [x] Live Wazuh stack brought up via `docker compose` *(see Evidence)*
- [ ] Dashboard PNGs *(GUI capture — see `assets/README.md`)*

---

## Evidence

The stack runs locally end to end. To reproduce and capture proof:

```bash
cd docker
cp .env.example .env && ./generate-certs.sh && docker compose up -d
./capture-evidence.sh            # writes API/indexer evidence to ../assets/evidence/
```

`capture-evidence.sh` authenticates to the Wazuh API, confirms the custom rules are
loaded, injects an SSH brute-force burst, and queries the indexer for the resulting
alerts. For the dashboard PNGs, open **https://localhost:443** and capture the
Security-events and MITRE ATT&CK views (`assets/README.md` lists the shots to grab).

---

## License

MIT — see [`LICENSE`](LICENSE).
