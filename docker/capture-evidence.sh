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
# rule 5710 ("failed login for a non-existent user") is what 100100 keys off, so
# the failures must name an *invalid* user — "Failed password for root" fires 5760
# instead and would not trip our rule. Follow the burst with a successful login
# from the same IP so 100101 (success-after-burst) fires too. active-responses.log
# is a monitored localfile in the default manager ossec.conf.
docker compose exec -T wazuh.manager sh -c '
  for i in $(seq 1 10); do
    echo "$(date "+%b %d %H:%M:%S") web01 sshd[33$i]: Failed password for invalid user admin from 203.0.113.7 port 5151$i ssh2" >> /var/ossec/logs/active-responses.log
  done
  echo "$(date "+%b %d %H:%M:%S") web01 sshd[3399]: Accepted password for root from 203.0.113.7 port 51599 ssh2" >> /var/ossec/logs/active-responses.log
' 2>/dev/null
sleep 12

echo "[*] 4/4 query the indexer for the SentinelOps detections we just triggered"
curl -sk -u "admin:${INDEXER_PASSWORD}" \
  "$IDX/wazuh-alerts*/_search?size=5&sort=timestamp:desc" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"terms":{"rule.id":["100100","100101"]}}}' | tee "$OUT/03-indexer-alerts.json" | head -40

echo
echo "[+] Evidence written to $OUT/"
echo "    For the dashboard PNGs, open https://localhost:443 (login from .env) and capture:"
echo "      - Security events / alerts overview"
echo "      - MITRE ATT&CK module after running an Atomic Red Team test"
