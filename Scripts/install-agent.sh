#!/usr/bin/env bash
set -euo pipefail

VAULT_URL="${VAULT_URL:-http://localhost:8080}"
TENANT_ID="${1:-}"
SECRET="${2:-}"
AGENT_NAME="${3:-default-agent}"

if [ -z "$TENANT_ID" ] || [ -z "$SECRET" ]; then
  echo "Verwendung: VAULT_URL=http://... ./install-agent.sh <TENANT_ID> <ENROLLMENT_SECRET> [AGENT_NAME]"
  exit 1
fi

if ! command -v jq &> /dev/null; then
  echo "[!] jq ist nicht installiert. Bitte installieren."
  exit 1
fi

echo "[*] Registriere Agent '${AGENT_NAME}' für Tenant '${TENANT_ID}'..."
PAYLOAD=$(jq -n \
  --arg tid "$TENANT_ID" \
  --arg sec "$SECRET" \
  --arg name "$AGENT_NAME" \
  '{tenant_id: $tid, enrollment_secret: $sec, agent_name: $name, scopes: ["agent:ingest-only"]}')

RESPONSE=$(curl -s -X POST "${VAULT_URL}/api/v1/agents/enroll" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

TOKEN=$(echo "$RESPONSE" | grep -o '"token":"[^"]*' | sed 's/"token":"//')
if [ -z "$TOKEN" ]; then
  echo "[!] Fehler beim Enrollment: $RESPONSE"
  exit 1
fi

sudo mkdir -p /etc/auditanchor
cat <<EOF | sudo tee /etc/auditanchor/agent.env > /dev/null
VAULT_URL=${VAULT_URL}
TENANT_ID=${TENANT_ID}
BEARER_TOKEN=${TOKEN}
EOF
sudo chmod 600 /etc/auditanchor/agent.env
echo "[+] Agent erfolgreich enrolled. Konfiguration unter /etc/auditanchor/agent.env abgelegt."
