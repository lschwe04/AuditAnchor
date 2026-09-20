# AuditAnchor Evidence-Vault

GoBD- und DSGVO-konformer Evidenz- und Audit-Vault in Go mit Zero-Trust-Chaining, Cryptographic Erasure und Agenten-Enrollment.

## Quickstart (Dev)
```bash
docker compose -f deployments/docker/docker-compose.yml up -d
go run cmd/vault/main.go

Agenten-Onboarding

VAULT_URL=http://localhost:8080 ./install-agent.sh my-tenant-id super-secret-enrollment-key my-agent-01

Dokumentation

Siehe api/openapi.yaml für API-Spezifikationen.

