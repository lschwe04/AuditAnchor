CREATE TABLE IF NOT EXISTS evidence_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_node_id VARCHAR(64) NOT NULL,
    evidence_type VARCHAR(64) NOT NULL, -- e.g., 'gobd_log', 'system_audit'
    sha256_hash CHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    retention_until TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_evidence_hash UNIQUE (tenant_id, sha256_hash)
);

CREATE INDEX idx_evidence_tenant_time ON evidence_records(tenant_id, created_at DESC);
