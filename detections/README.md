# Detections (detection-as-code)

Detection logic lives here as version-controlled [Sigma](https://github.com/SigmaHQ/sigma)
rules. They are backend-agnostic: the CI pipeline validates them and they can be
converted to the query language of whatever SIEM is deployed (the lab uses Wazuh;
the same rules convert cleanly to Elastic/OpenSearch, Splunk, etc.).

## Catalog

| Rule | File | ATT&CK | Type | Severity |
|------|------|--------|------|----------|
| SSH brute force from single source | `sigma/linux/lnx_ssh_bruteforce.yml` | T1110.001 | correlation (event_count) | high |
| Sudo running/downloading remote payload | `sigma/linux/lnx_sudo_remote_payload.yml` | T1059.004, T1105 | detection | high |
| Windows account brute force (4625) | `sigma/windows/win_failed_logon_bruteforce.yml` | T1110 | correlation (event_count) | high |
| New account added to privileged group | `sigma/windows/win_new_admin_account.yml` | T1136.001, T1098 | detection | medium |
| New Windows service installed (7045) | `sigma/windows/win_service_install.yml` | T1543.003 | detection | medium |
| Horizontal port scan | `sigma/network/net_port_scan.yml` | T1046 | correlation (value_count) | medium |
| C2 beaconing to uncommon port | `sigma/network/net_c2_beacon.yml` | T1071, T1571 | correlation (event_count) | high |

## Field convention

Rules match against the **normalized ECS-style schema** produced by
`ingestion/parsers/` (e.g. `source.ip`, `event.action`, `extra.event_id`), so the
same field means the same thing across Windows, Linux, and network telemetry.

## Validating locally (what CI runs)

```bash
pip install sigma-cli
sigma check detections/sigma -i -x attacktag
```

> **Why `-x attacktag`:** pySigma 3.0.2 bundles a non-standard ATT&CK tactic
> dataset (it lists `stealth` / `defense-impairment` instead of the real tactics),
> so its tactic-tag validator produces false positives against correct tags. We
> exclude that single validator and keep every other check strict (`-i` fails the
> build on any other issue). The technique tags (`attack.tXXXX`) are still
> validated for format.

## Correlation rules

The brute-force, port-scan, and beaconing detections use Sigma **correlation**
rules (the modern replacement for the deprecated `| count()` pipe aggregation):
a base rule defines the atomic event, and a correlation rule counts/aggregates it
over a time window grouped by an entity (e.g. `source.ip`). See any of the
correlation files for the two-document structure.
