CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- MSP Tenant Lookup / Stammdaten-Basis für den Start
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(64) PRIMARY KEY,
    display_name VARCHAR(255) NOT NULL,
    retention_days INT NOT NULL DEFAULT 3650,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Seed 3 Standard-Mandanten für 1-Click Systemhaus-Tests
INSERT INTO tenants (tenant_id, display_name) VALUES
    ('tenant-alpha', 'Kunde Alpha GmbH'),
    ('tenant-beta', 'Beta Logistics AG'),
    ('tenant-gamma', 'Gamma Steuerberatung')
ON CONFLICT (tenant_id) DO NOTHING;
