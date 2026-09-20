CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Evidenz-Blobs (Rohdaten + Krypto-Stempel aus ingest.go)
CREATE TABLE IF NOT EXISTS evidence_blobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    blob_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL,
    content_hash CHAR(64) NOT NULL,
    payload_json JSONB NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    hmac_sig CHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_evidence_blobs_tenant_time ON evidence_blobs(tenant_id, timestamp DESC);
CREATE INDEX idx_evidence_blobs_hash ON evidence_blobs(content_hash);

-- Fälschungssichere Audit-Chain (aus audit.go mit FOR UPDATE Row-Lock Chaining)
CREATE TABLE IF NOT EXISTS evidence_audit_chain (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    current_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_audit_chain_tenant_latest ON evidence_audit_chain(tenant_id, id DESC);
