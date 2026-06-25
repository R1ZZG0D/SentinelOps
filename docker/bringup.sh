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
# wazuh-control status exits non-zero on a single-node manager (clusterd,
# logcollector, maild, etc. are legitimately not running). Under `pipefail`
# that non-zero status would propagate through the pipe and the `until` loop
# would never see success, so capture the output first and let only grep decide.
until out=$(docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control status 2>/dev/null); \
      printf '%s' "$out" | grep -q "wazuh-analysisd is running"; do sleep 10; done

echo "[*] deploying custom detection rules..."
./deploy-rules.sh

# The manager's REST API users (wazuh = admin, wazuh-wui = the dashboard's
# account) live in the manager's RBAC database (a named volume) and ship with
# image-default passwords, so on a fresh stack they won't match .env. Sync both:
#   wazuh-wui -> API_PASSWORD        (so the dashboard can reach the manager)
#   wazuh     -> API_ADMIN_PASSWORD  (so the admin user isn't a default cred)
# Idempotent: authentication tries the configured admin password first, then the
# image default, so re-running after the password has been rotated still works.
echo "[*] syncing the Wazuh API passwords (wazuh-wui, wazuh) from .env..."
api_token() {
  # -f makes curl exit non-zero with empty output on HTTP 401, so a failed
  # password is skipped rather than mistaken for a token (the API returns a
  # JSON error body, not an empty one, on bad credentials).
  local p t
  for p in "${API_ADMIN_PASSWORD}" wazuh; do
    t=$(curl -fsk -u "wazuh:${p}" "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null) \
      && [ -n "$t" ] && { printf '%s' "$t"; return 0; }
  done
  return 1
}
until API_TOKEN=$(api_token); do sleep 5; done
USERS=$(curl -sk -H "Authorization: Bearer $API_TOKEN" "https://localhost:55000/security/users")
uid_of() { printf '%s' "$USERS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(next(u['id'] for u in d['data']['affected_items'] if u['username']=='$1'))"; }
WUI_ID=$(uid_of wazuh-wui)
ADM_ID=$(uid_of wazuh)
set_pw() {
  curl -sk -X PUT -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
    -d "{\"password\":\"$2\"}" "https://localhost:55000/security/users/$1" >/dev/null
}
set_pw "$WUI_ID" "${API_PASSWORD}"
# Change the admin user last so the bearer token (already issued) stays valid.
set_pw "$ADM_ID" "${API_ADMIN_PASSWORD}"
# Restart the dashboard so it reconnects with the now-correct API password
# instead of waiting out its retry interval.
docker compose restart wazuh.dashboard >/dev/null

echo
echo "[+] Stack is up."
echo "    Dashboard: https://localhost:443   (login: admin / \$INDEXER_PASSWORD from .env)"
echo "    Capture evidence with: ./capture-evidence.sh"
