CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(64) PRIMARY KEY,
    display_name VARCHAR(255) NOT NULL,
    retention_policy_days INT NOT NULL DEFAULT 3650, -- 10 Jahre GoBD Standard
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO tenants (tenant_id, display_name) VALUES
    ('tenant-alpha', 'Kunde Alpha GmbH'),
    ('tenant-beta', 'Beta Logistics AG'),
    ('tenant-gamma', 'Gamma Steuerberatung')
ON CONFLICT (tenant_id) DO NOTHING;
