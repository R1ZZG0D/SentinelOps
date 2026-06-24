# Wazuh SIEM stack

Single-node Wazuh deployment for the SentinelOps lab: **manager** (rule engine),
**indexer** (OpenSearch storage), and **dashboard** (UI).

## Requirements

- Docker + Docker Compose
- ~4 GB free disk, ~4 GB RAM available to Docker
- Linux/macOS: set `vm.max_map_count` for the indexer:
  ```bash
  sudo sysctl -w vm.max_map_count=262144   # Linux
  # Docker Desktop (macOS) applies this inside its VM automatically on recent versions
  ```

## Bring it up

```bash
cp .env.example .env          # then edit every credential
./generate-certs.sh           # one-time TLS cert generation
docker compose up -d
docker compose ps             # wait until all three are healthy (~1-2 min)
```

Open the dashboard at **https://localhost:443** (self-signed cert warning is expected).
Log in with the `DASHBOARD_*` credentials from your `.env`.

## Send logs to it

- **Linux/network syslog:** point a host at `udp/514` on the manager.
- **Agents (recommended):** install the Wazuh agent on a lab endpoint and enroll
  against `tcp/1515`; events flow over `tcp/1514`.
- **Custom rules:** edit `config/wazuh/local_rules.xml` (mounted into the manager)
  and restart: `docker compose restart wazuh.manager`.

## Tear it down (reclaim disk)

```bash
docker compose down            # keep data volumes
docker compose down -v         # also delete indexed data (frees the most disk)
```

> The rest of SentinelOps (parsers, Sigma rules, CI, triage assistant) runs
> **without** this stack, so you can tear it down between demos and still develop.

## Notes on the config

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Service definitions, ports, volumes. |
| `.env.example` | Credential template (copy to `.env`). |
| `generate-certs.sh` | Produces the TLS certs the stack mounts. |
| `config/certs/config.yml` | Node/SAN definitions for the cert generator. |
| `config/wazuh/wazuh.indexer.yml` | OpenSearch security + single-node config. |
| `config/wazuh/local_rules.xml` | SentinelOps custom detection rules (Wazuh-native). |
