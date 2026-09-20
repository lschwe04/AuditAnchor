CREATE TABLE IF NOT EXISTS tenant_webhook_secrets (
    tenant_id VARCHAR(64) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    integration_name VARCHAR(64) NOT NULL, -- e.g., 'ninjaone', 'prtg', 'generic'
    secret_value VARCHAR(255) NOT NULL,    -- AEAD/AES-GCM oder HMAC Secret (Rohwert/Base64)
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, integration_name)
);
