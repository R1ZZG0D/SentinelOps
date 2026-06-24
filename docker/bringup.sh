#!/usr/bin/env bash
# One-command bring-up for the SentinelOps Wazuh stack.
# Handles the operational steps that aren't obvious from `docker compose up`:
#   1. credentials + TLS certs
#   2. vm.max_map_count for OpenSearch
#   3. start the stack
#   4. initialize the OpenSearch security index (securityadmin)
#   5. deploy the custom detection rules to the running manager
#
# Usage:  ./bringup.sh
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || cp .env.example .env
set -a; . ./.env; set +a

if [ ! -f config/certs/root-ca.pem ]; then
  echo "[*] generating TLS certificates..."
  ./generate-certs.sh
fi

echo "[*] ensuring vm.max_map_count >= 262144 in the Docker VM..."
docker run --rm --privileged --pid=host alpine sh -c "sysctl -w vm.max_map_count=262144" >/dev/null 2>&1 || \
  echo "    (could not set automatically — set it on the Docker host if the indexer fails to start)"

echo "[*] starting the stack..."
docker compose up -d

echo "[*] waiting for the indexer to accept connections (slow under emulation)..."
until curl -sk https://localhost:9200 >/dev/null 2>&1; do sleep 5; done

echo "[*] initializing the OpenSearch security index..."
docker compose exec -T wazuh.indexer bash -c '
  export JAVA_HOME=/usr/share/wazuh-indexer/jdk
  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv \
    -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
    -cert /usr/share/wazuh-indexer/certs/admin.pem \
    -key /usr/share/wazuh-indexer/certs/admin-key.pem -h localhost -p 9200 -icl' | tail -1

echo "[*] waiting for the manager analysis engine..."
until docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control status 2>/dev/null \
      | grep -q "wazuh-analysisd is running"; do sleep 10; done

echo "[*] deploying custom detection rules..."
./deploy-rules.sh

echo
echo "[+] Stack is up."
echo "    Dashboard: https://localhost:443   (indexer login: admin / <image default>)"
echo "    Capture evidence with: ./capture-evidence.sh"
