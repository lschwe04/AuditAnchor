-- migrations/09_agent_tokens.sql
CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    token_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    enrollment_secret VARCHAR(255) NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_agent_enrollment_tenant ON agent_enrollment_tokens(tenant_id);
