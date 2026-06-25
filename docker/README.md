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

**One command** (handles certs, security init, and rule deployment):

```bash
./bringup.sh
```

Or step by step:

```bash
cp .env.example .env          # then edit every credential
./generate-certs.sh           # one-time TLS cert generation
docker compose up -d          # start the 3 services (slow first boot under emulation)
# initialize the OpenSearch security index (see bringup.sh for the securityadmin call)
./deploy-rules.sh             # push the custom detection rules to the running manager
```

Open the dashboard at **https://localhost:443** (self-signed cert warning is expected).
Log in as `admin` with the `INDEXER_PASSWORD` you set in `.env`. The bring-up wires
your `.env` credentials into the stack: `INDEXER_PASSWORD`/`DASHBOARD_PASSWORD` are
hashed into the indexer's `internal_users.yml` (admin / kibanaserver) and loaded by
`securityadmin`, and the manager's REST API users are rotated off their image
defaults — `API_PASSWORD` for `wazuh-wui` (the dashboard's account) and
`API_ADMIN_PASSWORD` for the `wazuh` admin user. The API password sync is idempotent:
it authenticates with the configured admin password first, falling back to the image
default, so re-running `./bringup.sh` after rotation still works.

The step-by-step path above skips the credential wiring — prefer `./bringup.sh`, which
does it in order. If you run the steps by hand, replicate the `securityadmin` and
`wazuh-wui` password calls from `bringup.sh`.

> **Apple Silicon note:** these are `linux/amd64` images, so they run under emulation
> on arm64 Macs — functional but slow to boot (give the indexer a few minutes).

## Send logs to it

- **Linux/network syslog:** point a host at `udp/514` on the manager.
- **Agents (recommended):** install the Wazuh agent on a lab endpoint and enroll
  against `tcp/1515`; events flow over `tcp/1514`.
- **Custom rules:** edit `config/wazuh/local_rules.xml`, then run `./deploy-rules.sh`
  to push it to the running manager and reload the engine. (Rules are deployed to the
  manager, not bind-mounted — a static mount into `/var/ossec/etc/` stops the manager
  from restoring its default `ossec.conf` on first boot.)

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
