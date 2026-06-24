# Incident-response runbooks

One runbook per high-value detection. Each follows the same structure so an analyst
can work it under pressure without thinking about format: **triage questions →
true/false-positive criteria → containment → eradication → recovery → tuning**.

The structure mirrors the SANS IR lifecycle (Preparation, Identification,
Containment, Eradication, Recovery, Lessons Learned) scoped to a single detection.

| Runbook | Detection | ATT&CK |
|---------|-----------|--------|
| [SSH brute force / account compromise](ir-ssh-bruteforce.md) | `lnx_ssh_bruteforce.yml`, `100101` | T1110.001 |
| [C2 beaconing](ir-c2-beacon.md) | `net_c2_beacon.yml` | T1071, T1571 |

New runbooks start from [`template.md`](template.md).

> The **Tuning** section of each runbook is where false-positive decisions are
> recorded — that history is the detection-engineering audit trail.
