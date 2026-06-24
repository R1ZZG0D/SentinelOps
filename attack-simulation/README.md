# Attack simulation

Reproducible adversary emulation mapped to the detections it should trigger. The
point isn't just to "run an attack" — it's to **close the loop**: every test names
the detection that must fire and the MITRE technique it exercises, so a miss is a
measurable detection gap, not a vibe.

## Tooling

- **[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)** — small,
  per-technique tests. Primary tool for this lab (lightweight, MITRE-indexed).
- **[Caldera](https://github.com/mitre/caldera)** — full adversary-emulation chains
  when you want an autonomous operation rather than single atomics.

Run atomics from a lab endpoint with the Wazuh agent installed, then watch the
detections fire in the dashboard and triage the resulting alerts.

```powershell
# Windows (PowerShell) — install the framework
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Invoke-AtomicTest T1110.001            # SSH/Windows brute force
```

```bash
# Linux — see atomic-catalog.md for the manual command per test
hydra -l root -P rockyou.txt ssh://10.0.0.5     # exercises T1110.001
```

## The loop

1. Pick a technique from `atomic-catalog.md`.
2. Run the atomic test against a lab endpoint.
3. Confirm the mapped detection fires in Wazuh.
4. If it fires → triage the alert (feed it to `../triage-assistant/`).
5. If it doesn't → that's a detection gap: tune the rule or write a new one, and
   record it in `../detections/mitre_coverage.md`.

See `atomic-catalog.md` for the test-to-detection mapping.
