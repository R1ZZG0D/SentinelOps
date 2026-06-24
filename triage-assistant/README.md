# AI Triage Assistant

The differentiator of this lab: an LLM-augmented triage tool that takes one
enriched SOC alert and produces a **Tier-3-style investigation summary** plus a
**customer-facing recommendation** — the same deliverable an MDR analyst sends a
client, generated in seconds.

## What it does

```
alert JSON ─▶ enrich (GeoIP, threat-intel, asset CMDB)
           ─▶ score  (transparent 0-100 model — scoring.py)
           ─▶ narrate (Claude writes the investigation)  ──▶ Markdown report
```

- **Enrichment** (`enrichment/`) — adds GeoIP/ASN, threat-intel reputation, and
  asset criticality. Mocked + offline so the lab is deterministic.
- **Scoring** (`scoring.py`) — a transparent, auditable severity model. The LLM
  writes prose; it does **not** get to invent the score. Every point is explained.
- **Narration** (`triage.py`) — Claude (`claude-opus-4-8`, adaptive thinking)
  reconstructs the incident, maps it to MITRE ATT&CK, gives a true/false-positive
  verdict, and writes both a SOC and a customer summary.

## Run it

```bash
pip install -r requirements.txt          # only needed for online mode

# Offline (deterministic, no API key, no network) — great for CI/demos:
python3 triage.py sample_alerts/ssh_bruteforce.json --offline

# Online (LLM-authored narrative):
export ANTHROPIC_API_KEY=sk-ant-...
python3 triage.py sample_alerts/ssh_bruteforce.json
```

`TRIAGE_MODEL` overrides the model (default `claude-opus-4-8`).

## Why a transparent score behind an LLM?

In a real SOC you can't ship a customer a severity that came from a black box. The
scoring model is deterministic and explainable (detection level + asset criticality
+ threat-intel verdict + correlation depth), and the LLM is constrained to *use* it
rather than recompute it. That keeps the speed of an LLM with the auditability a
managed-detection customer expects.

## Sample alerts

| File | Scenario | Expected verdict |
|------|----------|------------------|
| `ssh_bruteforce.json` | Brute force → successful root login from a known-bad IP | TRUE POSITIVE (high) |
| `c2_beacon.json` | Repeated beacon to `203.0.113.7:4444` | TRUE POSITIVE (high) |
| `port_scan_falsepositive.json` | Scan from the internal vuln scanner | Requires review / likely FALSE POSITIVE |

The three sample alerts tell one continuous attack story — scan → brute force →
beacon — matching the telemetry in `../ingestion/sample_logs/` and the coverage
matrix in `../detections/mitre_coverage.md`.
