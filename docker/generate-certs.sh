#!/usr/bin/env bash
# Generate the TLS certificates the Wazuh single-node stack needs.
# Uses Wazuh's official cert tool so the SANs/structure match what the images expect.
# Run once before `docker compose up -d`. Certs land in ./config/certs/ (gitignored).
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p config/certs

echo "[*] Generating Wazuh certificates via the official wazuh-certs-generator image..."
docker run --rm \
  -v "$(pwd)/config/certs:/certs" \
  -v "$(pwd)/config/certs/config.yml:/config/certs.yml:ro" \
  wazuh/wazuh-certs-generator:0.0.2 || {
    cat <<'EOF'
[!] If the image pull failed, you can generate certs manually with the official tarball:
    https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
EOF
    exit 1
  }

echo "[+] Certificates written to config/certs/. You can now run: docker compose up -d"
