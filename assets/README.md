# Assets

Captured evidence from running the live Wazuh stack lives in [`evidence/`](evidence/).
It is produced by `docker/capture-evidence.sh` (terminal/API/indexer artifacts) plus
headless-browser screenshots of the dashboard at `https://localhost:443`:

| File | Capture |
|------|---------|
| `01-containers.txt` | `docker compose ps` — all three services up |
| `02-wazuh-api.json` | Wazuh API auth + custom rules `100100`/`100101` loaded |
| `03-indexer-alerts.json` | The two detections indexed (level 12 / 14, MITRE T1110) |
| `04-dashboard-home.png` | Dashboard overview — last-24h alert severity summary |
| `05-discover-alerts.png` | Discover filtered to the SentinelOps rule IDs |
| `06-mitre-attack.png` | MITRE ATT&CK module — Credential Access / Brute Force |
| `07-threat-hunting.png` | Threat Hunting module — 4 level-12+ alerts, MITRE breakdown |

To regenerate: bring the stack up (`docker/bringup.sh`), run `docker/capture-evidence.sh`,
then open the dashboard and capture the Threat Hunting and MITRE ATT&CK views.
