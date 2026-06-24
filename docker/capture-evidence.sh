#!/usr/bin/env bash
# Capture real evidence that the SentinelOps Wazuh stack is up and detecting.
# Writes terminal/API evidence to ../assets/evidence/ (gitignored secrets stay out).
# Run after `docker compose up -d` reports all three services healthy.
set -uo pipefail
cd "$(dirname "$0")"
OUT=../assets/evidence
mkdir -p "$OUT"

# Load credentials from .env
set -a; . ./.env; set +a
API="https://localhost:55000"
IDX="https://localhost:9200"

echo "[*] 1/4 container status"
docker compose ps | tee "$OUT/01-containers.txt"

echo "[*] 2/4 Wazuh API auth + manager info"
TOKEN=$(curl -sk -u "wazuh-wui:${API_PASSWORD}" -X POST "$API/security/user/authenticate?raw=true")
{
  echo "# GET /manager/info";        curl -sk -H "Authorization: Bearer $TOKEN" "$API/manager/info"
  echo; echo "# GET /cluster/status"; curl -sk -H "Authorization: Bearer $TOKEN" "$API/cluster/status"
  echo; echo "# GET /rules?rule_ids=100100,100101 (our custom rules loaded)"
  curl -sk -H "Authorization: Bearer $TOKEN" "$API/rules?rule_ids=100100,100101"
} | tee "$OUT/02-wazuh-api.json"

echo "[*] 3/4 inject an SSH brute-force burst into the manager log to trigger detection"
# Append failed-then-success sshd lines so rule 5710 -> our 100100/100101 fire.
docker compose exec -T wazuh.manager sh -c '
  for i in $(seq 1 10); do
    echo "$(date "+%b %d %H:%M:%S") web01 sshd[2$i]: Failed password for root from 203.0.113.7 port 5151$i ssh2" >> /var/ossec/logs/active-responses.log
  done
' 2>/dev/null
sleep 8

echo "[*] 4/4 query the indexer for recent alerts"
curl -sk -u "admin:${INDEXER_PASSWORD}" \
  "$IDX/wazuh-alerts*/_search?size=5&sort=timestamp:desc" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"match_all":{}}}' | tee "$OUT/03-indexer-alerts.json" | head -40

echo
echo "[+] Evidence written to $OUT/"
echo "    For the dashboard PNGs, open https://localhost:443 (login from .env) and capture:"
echo "      - Security events / alerts overview"
echo "      - MITRE ATT&CK module after running an Atomic Red Team test"
