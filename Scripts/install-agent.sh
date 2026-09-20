#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="/etc/auditanchor"
TOKEN_FILE="${CONFIG_DIR}/agent.token"
API_URL="${API_URL:-http://localhost:8080}"
TENANT_ID="${TENANT_ID:-}"
ENROLLMENT_SECRET="${ENROLLMENT_SECRET:-}"

if [[ $EUID -ne 0 ]]; then
   echo "Bitte als root ausführen (sudo ./install-agent.sh)" >&2
   exit 1
fi

if [[ -z "$TENANT_ID" \vert{}\vert{} -z "$ENROLLMENT_SECRET" ]]; then
    read -rp "Mandanten-ID (TENANT_ID): " TENANT_ID
    read -rsp "Enrollment-Secret (ENROLLMENT_SECRET): " ENROLLMENT_SECRET
    echo ""
fi

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

echo "Enrollment an ${API_URL}/api/v1/agents/enroll wird durchgeführt..."
PAYLOAD=$(jq -nc --arg tid "$TENANT_ID" --arg sec "$ENROLLMENT_SECRET" --arg name "$(hostname)" '{tenant_id: $tid, enrollment_secret: $sec, agent_name:$name}')

RESPONSE=$(curl -s -f -X POST "${API_URL}/api/v1/agents/enroll" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

TOKEN=$(echo "$RESPONSE" | jq -r '.token')
if [[ -z "$TOKEN" \vert{}\vert{} "$TOKEN" == "null" ]]; then
    echo "Fehler beim Enrollment: Ungültige Antwort vom Server." >&2
    exit 1
fi

echo "$TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
chown root:root "$TOKEN_FILE"

echo "Agent erfolgreich enrolled. Token gespeichert unter $TOKEN_FILE."
