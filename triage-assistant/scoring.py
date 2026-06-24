"""Transparent severity scoring.

The LLM writes the narrative, but severity is decided by an auditable, deterministic
model — so an analyst (or a customer) can always see *why* an alert scored the way
it did, rather than trusting a black box. Score is 0-100, mapped to a band.
"""

from __future__ import annotations

from typing import Any

# Detection rule level (Wazuh-style 0-15) contributes the base signal.
_RULE_WEIGHT = 3.0           # points per rule level
_CRITICALITY = {"critical": 25, "high": 18, "medium": 8, "low": 2, "unknown": 5}
_TI_VERDICT = {"malicious": 25, "suspicious": 12, "unknown": 0, "benign": -10}


def score_alert(alert: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, Any]:
    """Compute a 0-100 severity score with a per-factor breakdown."""
    factors: list[dict[str, Any]] = []

    level = int(alert.get("rule", {}).get("level", 0))
    rule_points = min(level * _RULE_WEIGHT, 45)
    factors.append({"factor": "detection_rule_level", "detail": f"level {level}", "points": round(rule_points, 1)})

    crit = enrichment.get("asset", {}).get("criticality", "unknown")
    crit_points = _CRITICALITY.get(crit, 5)
    factors.append({"factor": "asset_criticality", "detail": crit, "points": crit_points})

    verdict = enrichment.get("source_ip", {}).get("threat_intel", {}).get("verdict", "unknown")
    ti_points = _TI_VERDICT.get(verdict, 0)
    factors.append({"factor": "threat_intel_verdict", "detail": verdict, "points": ti_points})

    # Correlation: more related events in the incident = higher confidence.
    n_events = len(alert.get("related_events", []))
    corr_points = min(n_events, 10)
    factors.append({"factor": "correlated_events", "detail": f"{n_events} events", "points": corr_points})

    total = max(0, min(100, round(sum(f["points"] for f in factors))))
    band = (
        "critical" if total >= 80
        else "high" if total >= 60
        else "medium" if total >= 35
        else "low"
    )
    return {"score": total, "severity": band, "factors": factors}
