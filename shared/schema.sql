-- WebAppBH OAM-Compliant Relational Schema
-- PostgreSQL 15+ DDL — matches SQLAlchemy models in lib_webbh/database.py
-- Applied automatically via docker-entrypoint-initdb.d on first boot.

BEGIN;

-- =========================================================================
-- 1. campaigns (NEW — M1 Phase)
-- =========================================================================
CREATE TABLE IF NOT EXISTS campaigns (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    scope_config    JSONB,
    rate_limit      INTEGER NOT NULL DEFAULT 50,
    has_credentials BOOLEAN NOT NULL DEFAULT FALSE,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_campaigns_status ON campaigns (status);

-- =========================================================================
-- 2. targets (updated — M1 Phase: new columns)
-- =========================================================================
CREATE TABLE IF NOT EXISTS targets (
    id               SERIAL PRIMARY KEY,
    company_name     VARCHAR(255) NOT NULL,
    base_domain      VARCHAR(255) NOT NULL,
    target_profile   JSONB,
    last_playbook    VARCHAR(100),

    -- Campaign & hierarchy columns (M1)
    campaign_id      INTEGER REFERENCES campaigns(id),
    parent_target_id INTEGER REFERENCES targets(id),
    target_type      VARCHAR(20) NOT NULL DEFAULT 'seed',
    priority         INTEGER NOT NULL DEFAULT 50,
    wildcard         BOOLEAN NOT NULL DEFAULT FALSE,
    wildcard_count   INTEGER,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_targets_company_domain
    ON targets (company_name, base_domain);
CREATE INDEX IF NOT EXISTS ix_targets_parent ON targets (parent_target_id);
CREATE INDEX IF NOT EXISTS ix_targets_campaign ON targets (campaign_id);
CREATE INDEX IF NOT EXISTS ix_targets_priority ON targets (priority);

-- =========================================================================
-- 3. assets
-- =========================================================================
CREATE TABLE IF NOT EXISTS assets (
    id          SERIAL PRIMARY KEY,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_type  VARCHAR(50)  NOT NULL,
    asset_value VARCHAR(500) NOT NULL,
    source_tool VARCHAR(100),
    tech        JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_assets_target_id ON assets (target_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_target_type_value
    ON assets (target_id, asset_type, asset_value);
CREATE INDEX IF NOT EXISTS ix_assets_target_type ON assets (target_id, asset_type);
CREATE INDEX IF NOT EXISTS ix_assets_target_created ON assets (target_id, created_at);

-- =========================================================================
-- 4. identities
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
-- 5. locations
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
-- 6. observations
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
-- 7. cloud_assets
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
-- 8. parameters
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
-- 9. vulnerabilities (updated — M1 Phase: new columns)
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
    cvss_score  FLOAT,
    remediation TEXT,

    -- WSTG tracking columns (M1)
    section_id    VARCHAR(20),
    worker_type   VARCHAR(100),
    stage_name    VARCHAR(100),
    vuln_type     VARCHAR(100),
    confirmed     BOOLEAN NOT NULL DEFAULT FALSE,
    false_positive BOOLEAN NOT NULL DEFAULT FALSE,
    evidence      JSONB,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_vuln_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS ix_vulns_target_id ON vulnerabilities (target_id);
CREATE INDEX IF NOT EXISTS ix_vulns_asset_id  ON vulnerabilities (asset_id);
CREATE INDEX IF NOT EXISTS ix_vulns_severity  ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS ix_vulns_target_severity ON vulnerabilities (target_id, severity);
CREATE INDEX IF NOT EXISTS ix_vulns_target_created ON vulnerabilities (target_id, created_at);
CREATE INDEX IF NOT EXISTS ix_vulns_section ON vulnerabilities (section_id);
CREATE INDEX IF NOT EXISTS ix_vulns_worker ON vulnerabilities (worker_type);
CREATE INDEX IF NOT EXISTS ix_vulns_confirmed ON vulnerabilities (confirmed);

-- =========================================================================
-- 10. job_state (updated — M1 Phase: new columns)
-- =========================================================================
CREATE TABLE IF NOT EXISTS job_state (
    id                 SERIAL PRIMARY KEY,
    target_id          INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    container_name     VARCHAR(255) NOT NULL,
    current_phase      VARCHAR(100),
    status             VARCHAR(20) NOT NULL,
    last_seen          TIMESTAMPTZ,
    last_tool_executed VARCHAR(100),

    -- Stage tracking columns (M1)
    current_section_id VARCHAR(20),
    queued_at          TIMESTAMPTZ,
    started_at         TIMESTAMPTZ,
    completed_at       TIMESTAMPTZ,
    skipped            BOOLEAN NOT NULL DEFAULT FALSE,
    skip_reason        VARCHAR(500),
    retry_count        INTEGER NOT NULL DEFAULT 0,
    error              TEXT,

    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_job_status CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'PAUSED', 'STOPPED', 'KILLED', 'queued', 'running', 'complete', 'failed'))
);

CREATE INDEX IF NOT EXISTS ix_job_state_target_id ON job_state (target_id);
CREATE INDEX IF NOT EXISTS ix_job_state_status    ON job_state (status);
CREATE INDEX IF NOT EXISTS ix_jobstate_target_status ON job_state (target_id, status);
CREATE INDEX IF NOT EXISTS ix_jobstate_container_status ON job_state (container_name, status);
CREATE INDEX IF NOT EXISTS ix_jobstate_target_container ON job_state (target_id, container_name);

-- =========================================================================
-- 11. alerts
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
CREATE INDEX IF NOT EXISTS ix_alerts_target_read ON alerts (target_id, is_read);

-- =========================================================================
-- 12. api_schemas
-- =========================================================================
CREATE TABLE IF NOT EXISTS api_schemas (
    id             SERIAL PRIMARY KEY,
    target_id      INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id       INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    method         VARCHAR(10) NOT NULL,
    path           VARCHAR(2000) NOT NULL,
    params         JSONB,
    auth_required  BOOLEAN,
    content_type   VARCHAR(100),
    source_tool    VARCHAR(100),
    spec_type      VARCHAR(50),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_api_schemas_target_asset_method_path
    ON api_schemas (target_id, asset_id, method, path);

-- =========================================================================
-- 13. mobile_apps
-- =========================================================================
CREATE TABLE IF NOT EXISTS mobile_apps (
    id              SERIAL PRIMARY KEY,
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id        INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    platform        VARCHAR(10) NOT NULL,
    package_name    VARCHAR(500) NOT NULL,
    version         VARCHAR(100),
    permissions     JSONB,
    signing_info    JSONB,
    mobsf_score     FLOAT,
    decompiled_path VARCHAR(1000),
    source_url      VARCHAR(2000),
    source_tool     VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_mobile_apps_target_platform_pkg
    ON mobile_apps (target_id, platform, package_name);

-- =========================================================================
-- 14. asset_snapshots
-- =========================================================================
CREATE TABLE IF NOT EXISTS asset_snapshots (
    id           SERIAL PRIMARY KEY,
    target_id    INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scan_number  INTEGER NOT NULL,
    asset_count  INTEGER NOT NULL DEFAULT 0,
    asset_hashes JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_snapshot_target_scan
    ON asset_snapshots (target_id, scan_number);

-- =========================================================================
-- 15. bounty_submissions
-- =========================================================================
CREATE TABLE IF NOT EXISTS bounty_submissions (
    id                SERIAL PRIMARY KEY,
    target_id         INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    vulnerability_id  INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    platform          VARCHAR(50) NOT NULL,
    status            VARCHAR(50) NOT NULL,
    submission_url    VARCHAR(2000),
    expected_payout   FLOAT,
    actual_payout     FLOAT,
    notes             TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_bounty_submissions_target ON bounty_submissions (target_id);
CREATE INDEX IF NOT EXISTS ix_bounty_submissions_vuln ON bounty_submissions (vulnerability_id);

-- =========================================================================
-- 16. scheduled_scans
-- =========================================================================
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id              SERIAL PRIMARY KEY,
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    cron_expression VARCHAR(100) NOT NULL,
    playbook        VARCHAR(100) NOT NULL DEFAULT 'wide_recon',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_scheduled_scans_target_cron
    ON scheduled_scans (target_id, cron_expression);

-- =========================================================================
-- 17. scope_violations
-- =========================================================================
CREATE TABLE IF NOT EXISTS scope_violations (
    id             SERIAL PRIMARY KEY,
    target_id      INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    tool_name      VARCHAR(100) NOT NULL,
    input_value    VARCHAR(2000) NOT NULL,
    violation_type VARCHAR(50) NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_scope_violations_target ON scope_violations (target_id);

-- =========================================================================
-- 18. custom_playbooks
-- =========================================================================
CREATE TABLE IF NOT EXISTS custom_playbooks (
    id           SERIAL PRIMARY KEY,
    name         VARCHAR(100) NOT NULL UNIQUE,
    description  TEXT,
    stages       JSONB,
    concurrency  JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- 19. escalation_contexts (NEW — M1 Phase)
-- =========================================================================
CREATE TABLE IF NOT EXISTS escalation_contexts (
    id                   SERIAL PRIMARY KEY,
    target_id            INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    vulnerability_id     INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    access_type          VARCHAR(100) NOT NULL,
    access_method        TEXT NOT NULL,
    session_data         TEXT,
    data_exposed         TEXT,
    severity             VARCHAR(20) NOT NULL,
    section_id           VARCHAR(20),
    consumed_by_chain    BOOLEAN NOT NULL DEFAULT FALSE,
    chain_findings       JSONB,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_escalation_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS ix_escalation_target ON escalation_contexts (target_id);
CREATE INDEX IF NOT EXISTS ix_escalation_consumed ON escalation_contexts (consumed_by_chain);
CREATE INDEX IF NOT EXISTS ix_escalation_vuln ON escalation_contexts (vulnerability_id);

-- =========================================================================
-- 20. chain_findings (NEW — M1 Phase)
-- =========================================================================
CREATE TABLE IF NOT EXISTS chain_findings (
    id                      SERIAL PRIMARY KEY,
    target_id               INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    escalation_context_id   INTEGER NOT NULL REFERENCES escalation_contexts(id) ON DELETE CASCADE,
    chain_description       TEXT NOT NULL,
    entry_vulnerability_id  INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    linked_vulnerability_ids JSONB,
    total_impact            TEXT,
    severity                VARCHAR(20) NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_chain_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS ix_chain_findings_target ON chain_findings (target_id);
CREATE INDEX IF NOT EXISTS ix_chain_findings_escalation ON chain_findings (escalation_context_id);
CREATE INDEX IF NOT EXISTS ix_chain_findings_entry_vuln ON chain_findings (entry_vulnerability_id);

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
            'campaigns', 'targets', 'assets', 'identities', 'locations',
            'observations', 'cloud_assets', 'parameters',
            'vulnerabilities', 'job_state', 'alerts',
            'api_schemas', 'mobile_apps', 'asset_snapshots',
            'bounty_submissions', 'scheduled_scans', 'scope_violations',
            'custom_playbooks', 'escalation_contexts', 'chain_findings'
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
