-- WebAppBH OAM-Compliant Relational Schema
-- PostgreSQL 15+ DDL — matches SQLAlchemy models in lib_webbh/database.py
-- Applied automatically via docker-entrypoint-initdb.d on first boot.

BEGIN;

-- =========================================================================
-- 1. targets
-- =========================================================================
CREATE TABLE IF NOT EXISTS targets (
    id          SERIAL PRIMARY KEY,
    company_name VARCHAR(255) NOT NULL,
    base_domain  VARCHAR(255) NOT NULL,
    target_profile JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_targets_company_domain
    ON targets (company_name, base_domain);

-- =========================================================================
-- 2. assets
-- =========================================================================
CREATE TABLE IF NOT EXISTS assets (
    id          SERIAL PRIMARY KEY,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_type  VARCHAR(50)  NOT NULL,
    asset_value VARCHAR(500) NOT NULL,
    source_tool VARCHAR(100),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_assets_target_id ON assets (target_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_target_type_value
    ON assets (target_id, asset_type, asset_value);

-- =========================================================================
-- 3. identities
-- =========================================================================
CREATE TABLE IF NOT EXISTS identities (
    id           SERIAL PRIMARY KEY,
    target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asn          VARCHAR(50),
    organization VARCHAR(255),
    whois_data   JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_identities_target_id ON identities (target_id);

-- =========================================================================
-- 4. locations
-- =========================================================================
CREATE TABLE IF NOT EXISTS locations (
    id        SERIAL PRIMARY KEY,
    asset_id  INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port      INTEGER NOT NULL,
    protocol  VARCHAR(20),
    service   VARCHAR(100),
    state     VARCHAR(20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_locations_asset_id ON locations (asset_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_locations_asset_port_proto
    ON locations (asset_id, port, protocol);

-- =========================================================================
-- 5. observations
-- =========================================================================
CREATE TABLE IF NOT EXISTS observations (
    id          SERIAL PRIMARY KEY,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tech_stack  JSONB,
    page_title  VARCHAR(500),
    status_code INTEGER,
    headers     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_observations_asset_id ON observations (asset_id);

-- =========================================================================
-- 6. cloud_assets
-- =========================================================================
CREATE TABLE IF NOT EXISTS cloud_assets (
    id         SERIAL PRIMARY KEY,
    target_id  INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    provider   VARCHAR(20)  NOT NULL,
    asset_type VARCHAR(100) NOT NULL,
    url        VARCHAR(1000),
    is_public  BOOLEAN NOT NULL DEFAULT FALSE,
    findings   JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_cloud_provider CHECK (provider IN ('AWS', 'Azure', 'GCP', 'Other'))
);

CREATE INDEX IF NOT EXISTS ix_cloud_assets_target_id ON cloud_assets (target_id);

-- =========================================================================
-- 7. parameters
-- =========================================================================
CREATE TABLE IF NOT EXISTS parameters (
    id          SERIAL PRIMARY KEY,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    param_name  VARCHAR(255) NOT NULL,
    param_value TEXT,
    source_url  VARCHAR(2000),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_parameters_asset_id ON parameters (asset_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_parameters_asset_name
    ON parameters (asset_id, param_name);

-- =========================================================================
-- 8. vulnerabilities
-- =========================================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          SERIAL PRIMARY KEY,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id    INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    severity    VARCHAR(20) NOT NULL,
    title       VARCHAR(500) NOT NULL,
    description TEXT,
    poc         TEXT,
    source_tool VARCHAR(100),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_vuln_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS ix_vulns_target_id ON vulnerabilities (target_id);
CREATE INDEX IF NOT EXISTS ix_vulns_asset_id  ON vulnerabilities (asset_id);
CREATE INDEX IF NOT EXISTS ix_vulns_severity  ON vulnerabilities (severity);

-- =========================================================================
-- 9. job_state
-- =========================================================================
CREATE TABLE IF NOT EXISTS job_state (
    id                 SERIAL PRIMARY KEY,
    target_id          INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    container_name     VARCHAR(255) NOT NULL,
    current_phase      VARCHAR(100),
    status             VARCHAR(20) NOT NULL,
    last_seen          TIMESTAMPTZ,
    last_tool_executed VARCHAR(100),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_job_status CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS ix_job_state_target_id ON job_state (target_id);
CREATE INDEX IF NOT EXISTS ix_job_state_status    ON job_state (status);

-- =========================================================================
-- 10. alerts
-- =========================================================================
CREATE TABLE IF NOT EXISTS alerts (
    id               SERIAL PRIMARY KEY,
    target_id        INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    alert_type       VARCHAR(100) NOT NULL,
    message          TEXT NOT NULL,
    is_read          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_alerts_target_id ON alerts (target_id);
CREATE INDEX IF NOT EXISTS ix_alerts_unread    ON alerts (is_read) WHERE is_read = FALSE;

-- =========================================================================
-- Trigger: auto-update updated_at on row modification
-- =========================================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOR tbl IN
        SELECT unnest(ARRAY[
            'targets', 'assets', 'identities', 'locations',
            'observations', 'cloud_assets', 'parameters',
            'vulnerabilities', 'job_state', 'alerts'
        ])
    LOOP
        EXECUTE format(
            'CREATE OR REPLACE TRIGGER trg_%s_updated_at
             BEFORE UPDATE ON %I
             FOR EACH ROW EXECUTE FUNCTION update_updated_at()',
            tbl, tbl
        );
    END LOOP;
END;
$$;

COMMIT;
