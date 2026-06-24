#!/usr/bin/env bash
# Deploy SentinelOps custom rules to the running Wazuh manager and reload.
# This is the local, hands-on version of what the CI pipeline's deploy job does:
# push validated detection content to the manager and restart it.
#
# Run after `docker compose up -d` and the manager is healthy.
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Copying local_rules.xml into the manager..."
docker compose cp config/wazuh/local_rules.xml wazuh.manager:/var/ossec/etc/rules/local_rules.xml

echo "[*] Restarting the analysis engine to load the new ruleset..."
docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control restart >/dev/null

echo "[+] Deployed. Verify with:"
echo "    docker compose exec wazuh.manager grep -c sentinelops /var/ossec/etc/rules/local_rules.xml"
