"""SentinelOps AI triage assistant.

Takes one enriched SOC alert and produces a Tier-3-style investigation summary plus
a customer-facing recommendation. Two modes:

  * online  — uses Claude (Anthropic API) to write the narrative. Default when
              ANTHROPIC_API_KEY is set.
  * offline — a deterministic, rules-based report. Used when no API key is present
              or --offline is passed, so the tool still runs in CI and in demos.

Severity is always decided by the transparent scoring model in scoring.py — the LLM
writes prose, it does not get to invent the score.

Usage:
    python3 triage.py sample_alerts/ssh_bruteforce.json
    python3 triage.py sample_alerts/ssh_bruteforce.json --offline
    ANTHROPIC_API_KEY=sk-ant-... python3 triage.py sample_alerts/c2_beacon.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from enrichment import enrich
from scoring import score_alert

HERE = Path(__file__).resolve().parent
SYSTEM_PROMPT = (HERE / "prompts" / "system_prompt.md").read_text(encoding="utf-8")

# Default to the most capable current Claude model; override with TRIAGE_MODEL.
MODEL = os.environ.get("TRIAGE_MODEL", "claude-opus-4-8")


def build_context(alert: dict[str, Any]) -> dict[str, Any]:
    """Enrich + score an alert into the bundle handed to the analyst/LLM."""
    enrichment = enrich(alert)
    scoring = score_alert(alert, enrichment)
    return {"alert": alert, "enrichment": enrichment, "scoring": scoring}


# --- Online (Claude) -------------------------------------------------------

def triage_online(context: dict[str, Any]) -> str:
    import anthropic  # imported lazily so offline mode needs no dependency

    client = anthropic.Anthropic()
    user_content = (
        "Investigate and write up this enriched alert. The severity score and "
        "factor breakdown are already computed — use them, do not recompute.\n\n"
        "```json\n" + json.dumps(context, indent=2) + "\n```"
    )
    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": user_content}],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()


# --- Offline (deterministic) ----------------------------------------------

def triage_offline(context: dict[str, Any]) -> str:
    alert = context["alert"]
    enr = context["enrichment"]
    sc = context["scoring"]

    rule = alert.get("rule", {})
    techniques = rule.get("mitre", [])
    src = enr["source_ip"]
    asset = enr["asset"]
    ti = src.get("threat_intel", {})

    malicious = ti.get("verdict") == "malicious"
    verdict = "TRUE POSITIVE" if (sc["score"] >= 60 or malicious) else "REQUIRES ANALYST REVIEW"
    confidence = "high" if (malicious and sc["score"] >= 60) else "medium"

    factor_lines = "\n".join(
        f"- {f['factor']}: {f['detail']} (+{f['points']})" for f in sc["factors"]
    )
    attack_lines = "\n".join(f"- {t}" for t in techniques) or "- (none tagged)"

    return f"""## Verdict
{verdict} — confidence: {confidence} (severity score {sc['score']}/100, band: {sc['severity'].upper()})

## What happened
Detection `{rule.get('id', '?')}` ({rule.get('description', 'n/a')}) fired on asset
**{asset.get('value')}** ({asset.get('role')}, criticality: {asset.get('criticality')}).
Source **{src.get('value')}** geolocates to {src.get('geoip', {}).get('country')}
({src.get('geoip', {}).get('asn')}); threat-intel verdict is **{ti.get('verdict')}**
{('— categories: ' + ', '.join(ti.get('categories', []))) if ti.get('categories') else ''}.
The incident bundles {len(alert.get('related_events', []))} correlated events.

## Evidence & ATT&CK mapping
{attack_lines}

### Severity factor breakdown
{factor_lines}

## Recommended actions (SOC)
1. Containment: block source {src.get('value')} at the perimeter firewall; preserve
   the host's current state (memory/disk) before any cleanup.
2. Eradication: validate whether the source achieved access on {asset.get('value')};
   reset any potentially exposed credentials and revoke active sessions.
3. Recovery: confirm no persistence was established, then restore normal access and
   monitor the source/asset pair for recurrence.

## Customer summary
We observed activity from {src.get('value')} ({src.get('geoip', {}).get('country')})
against your **{asset.get('role')}** ({asset.get('value')}), assessed as
**{verdict.lower()}**. Most important next step: confirm the action above and rotate
any credentials that may have been exposed on this asset.

---
*Generated offline (deterministic rules engine). Set ANTHROPIC_API_KEY for the
LLM-authored investigation narrative.*"""


def run(alert_path: str, offline: bool) -> str:
    alert = json.loads(Path(alert_path).read_text(encoding="utf-8"))
    context = build_context(alert)
    use_offline = offline or not os.environ.get("ANTHROPIC_API_KEY")
    if use_offline:
        return triage_offline(context)
    try:
        return triage_online(context)
    except Exception as exc:  # never fail a triage because the API hiccuped
        print(f"# online triage failed ({exc}); falling back to offline", file=sys.stderr)
        return triage_offline(context)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AI-augmented SOC alert triage.")
    ap.add_argument("alert", help="path to an enriched alert JSON file")
    ap.add_argument("--offline", action="store_true", help="force the deterministic engine")
    args = ap.parse_args(argv)
    print(run(args.alert, args.offline))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
