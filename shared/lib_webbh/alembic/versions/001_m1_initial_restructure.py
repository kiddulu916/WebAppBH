"""M1 initial migration — add new tables and columns for WSTG restructure.

Creates: campaigns, escalation_contexts, chain_findings, api_schemas,
mobile_apps, asset_snapshots, bounty_submissions, scheduled_scans,
scope_violations, custom_playbooks.

Adds columns to: targets (campaign_id, parent_target_id, target_type,
priority, wildcard, wildcard_count, last_playbook),
vulnerabilities (section_id, worker_type, stage_name, vuln_type,
confirmed, false_positive, evidence, cvss_score, remediation),
job_state (current_section_id, queued_at, started_at, completed_at,
skipped, skip_reason, retry_count, error),
assets (tech), and new indexes across all tables.
"""

from alembic import op
import sqlalchemy as sa

revision = "001_m1_initial_restructure"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # New tables
    # ------------------------------------------------------------------
    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("scope_config", sa.JSON, nullable=True),
        sa.Column("rate_limit", sa.Integer, nullable=False, server_default="50"),
        sa.Column("has_credentials", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_campaigns_status", "campaigns", ["status"])

    op.create_table(
        "escalation_contexts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vulnerability_id", sa.Integer, sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("access_type", sa.String(100), nullable=False),
        sa.Column("access_method", sa.Text, nullable=False),
        sa.Column("session_data", sa.Text, nullable=True),
        sa.Column("data_exposed", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("section_id", sa.String(20), nullable=True),
        sa.Column("consumed_by_chain", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("chain_findings", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_escalation_target", "escalation_contexts", ["target_id"])
    op.create_index("ix_escalation_consumed", "escalation_contexts", ["consumed_by_chain"])
    op.create_index("ix_escalation_vuln", "escalation_contexts", ["vulnerability_id"])

    op.create_table(
        "chain_findings",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("escalation_context_id", sa.Integer, sa.ForeignKey("escalation_contexts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("chain_description", sa.Text, nullable=False),
        sa.Column("entry_vulnerability_id", sa.Integer, sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("linked_vulnerability_ids", sa.JSON, nullable=True),
        sa.Column("total_impact", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_chain_findings_target", "chain_findings", ["target_id"])
    op.create_index("ix_chain_findings_escalation", "chain_findings", ["escalation_context_id"])
    op.create_index("ix_chain_findings_entry_vuln", "chain_findings", ["entry_vulnerability_id"])

    op.create_table(
        "api_schemas",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer, sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("path", sa.String(2000), nullable=False),
        sa.Column("params", sa.JSON, nullable=True),
        sa.Column("auth_required", sa.Boolean, nullable=True),
        sa.Column("content_type", sa.String(100), nullable=True),
        sa.Column("source_tool", sa.String(100), nullable=True),
        sa.Column("spec_type", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_unique_constraint(
        "uq_api_schemas_target_asset_method_path",
        "api_schemas",
        ["target_id", "asset_id", "method", "path"],
    )

    op.create_table(
        "mobile_apps",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.Integer, sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("platform", sa.String(10), nullable=False),
        sa.Column("package_name", sa.String(500), nullable=False),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("permissions", sa.JSON, nullable=True),
        sa.Column("signing_info", sa.JSON, nullable=True),
        sa.Column("mobsf_score", sa.Float, nullable=True),
        sa.Column("decompiled_path", sa.String(1000), nullable=True),
        sa.Column("source_url", sa.String(2000), nullable=True),
        sa.Column("source_tool", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_unique_constraint(
        "uq_mobile_apps_target_platform_pkg",
        "mobile_apps",
        ["target_id", "platform", "package_name"],
    )

    op.create_table(
        "asset_snapshots",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_number", sa.Integer, nullable=False),
        sa.Column("asset_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("asset_hashes", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_unique_constraint("uq_snapshot_target_scan", "asset_snapshots", ["target_id", "scan_number"])

    op.create_table(
        "bounty_submissions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vulnerability_id", sa.Integer, sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("platform", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("submission_url", sa.String(2000), nullable=True),
        sa.Column("expected_payout", sa.Float, nullable=True),
        sa.Column("actual_payout", sa.Float, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_bounty_submissions_target", "bounty_submissions", ["target_id"])
    op.create_index("ix_bounty_submissions_vuln", "bounty_submissions", ["vulnerability_id"])

    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cron_expression", sa.String(100), nullable=False),
        sa.Column("playbook", sa.String(100), nullable=False, server_default="wide_recon"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_unique_constraint("uq_scheduled_scans_target_cron", "scheduled_scans", ["target_id", "cron_expression"])

    op.create_table(
        "scope_violations",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer, sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tool_name", sa.String(100), nullable=False),
        sa.Column("input_value", sa.String(2000), nullable=False),
        sa.Column("violation_type", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_scope_violations_target", "scope_violations", ["target_id"])

    op.create_table(
        "custom_playbooks",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("stages", sa.JSON, nullable=True),
        sa.Column("concurrency", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # ------------------------------------------------------------------
    # New columns on existing tables
    # ------------------------------------------------------------------

    # targets
    op.add_column("targets", sa.Column("campaign_id", sa.Integer, sa.ForeignKey("campaigns.id"), nullable=True))
    op.add_column("targets", sa.Column("parent_target_id", sa.Integer, sa.ForeignKey("targets.id"), nullable=True))
    op.add_column("targets", sa.Column("target_type", sa.String(20), nullable=False, server_default="seed"))
    op.add_column("targets", sa.Column("priority", sa.Integer, nullable=False, server_default="50"))
    op.add_column("targets", sa.Column("wildcard", sa.Boolean, nullable=False, server_default="false"))
    op.add_column("targets", sa.Column("wildcard_count", sa.Integer, nullable=True))
    op.add_column("targets", sa.Column("last_playbook", sa.String(100), nullable=True))
    op.create_index("ix_targets_parent", "targets", ["parent_target_id"])
    op.create_index("ix_targets_campaign", "targets", ["campaign_id"])
    op.create_index("ix_targets_priority", "targets", ["priority"])

    # vulnerabilities
    op.add_column("vulnerabilities", sa.Column("section_id", sa.String(20), nullable=True))
    op.add_column("vulnerabilities", sa.Column("worker_type", sa.String(100), nullable=True))
    op.add_column("vulnerabilities", sa.Column("stage_name", sa.String(100), nullable=True))
    op.add_column("vulnerabilities", sa.Column("vuln_type", sa.String(100), nullable=True))
    op.add_column("vulnerabilities", sa.Column("confirmed", sa.Boolean, nullable=False, server_default="false"))
    op.add_column("vulnerabilities", sa.Column("false_positive", sa.Boolean, nullable=False, server_default="false"))
    op.add_column("vulnerabilities", sa.Column("evidence", sa.JSON, nullable=True))
    op.add_column("vulnerabilities", sa.Column("cvss_score", sa.Float, nullable=True))
    op.add_column("vulnerabilities", sa.Column("remediation", sa.Text, nullable=True))
    op.create_index("ix_vulns_target_severity", "vulnerabilities", ["target_id", "severity"])
    op.create_index("ix_vulns_target_created", "vulnerabilities", ["target_id", "created_at"])
    op.create_index("ix_vulns_section", "vulnerabilities", ["section_id"])
    op.create_index("ix_vulns_worker", "vulnerabilities", ["worker_type"])
    op.create_index("ix_vulns_confirmed", "vulnerabilities", ["confirmed"])

    # job_state
    op.add_column("job_state", sa.Column("current_section_id", sa.String(20), nullable=True))
    op.add_column("job_state", sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("job_state", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("job_state", sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("job_state", sa.Column("skipped", sa.Boolean, nullable=False, server_default="false"))
    op.add_column("job_state", sa.Column("skip_reason", sa.String(500), nullable=True))
    op.add_column("job_state", sa.Column("retry_count", sa.Integer, nullable=False, server_default="0"))
    op.add_column("job_state", sa.Column("error", sa.Text, nullable=True))
    op.create_index("ix_jobstate_target_status", "job_state", ["target_id", "status"])
    op.create_index("ix_jobstate_container_status", "job_state", ["container_name", "status"])
    op.create_index("ix_jobstate_target_container", "job_state", ["target_id", "container_name"])

    # assets
    op.add_column("assets", sa.Column("tech", sa.JSON, nullable=True))
    op.create_index("ix_assets_target_type", "assets", ["target_id", "asset_type"])
    op.create_index("ix_assets_target_created", "assets", ["target_id", "created_at"])

    # alerts
    op.create_index("ix_alerts_target_read", "alerts", ["target_id", "is_read"])


def downgrade() -> None:
    # Drop new tables (order matters for FKs)
    op.drop_table("custom_playbooks")
    op.drop_table("scope_violations")
    op.drop_table("scheduled_scans")
    op.drop_table("bounty_submissions")
    op.drop_table("asset_snapshots")
    op.drop_table("mobile_apps")
    op.drop_table("api_schemas")
    op.drop_table("chain_findings")
    op.drop_table("escalation_contexts")
    op.drop_table("campaigns")

    # Remove new columns from targets
    op.drop_index("ix_targets_priority", table_name="targets")
    op.drop_index("ix_targets_campaign", table_name="targets")
    op.drop_index("ix_targets_parent", table_name="targets")
    op.drop_column("targets", "last_playbook")
    op.drop_column("targets", "wildcard_count")
    op.drop_column("targets", "wildcard")
    op.drop_column("targets", "priority")
    op.drop_column("targets", "target_type")
    op.drop_column("targets", "parent_target_id")
    op.drop_column("targets", "campaign_id")

    # Remove new columns from vulnerabilities
    for col in ["confirmed", "false_positive", "evidence", "cvss_score", "remediation",
                "section_id", "worker_type", "stage_name", "vuln_type"]:
        op.drop_column("vulnerabilities", col)
    for idx in ["ix_vulns_target_severity", "ix_vulns_target_created",
                "ix_vulns_section", "ix_vulns_worker", "ix_vulns_confirmed"]:
        op.drop_index(idx, table_name="vulnerabilities")

    # Remove new columns from job_state
    for col in ["current_section_id", "queued_at", "started_at", "completed_at",
                "skipped", "skip_reason", "retry_count", "error"]:
        op.drop_column("job_state", col)
    for idx in ["ix_jobstate_target_status", "ix_jobstate_container_status",
                "ix_jobstate_target_container"]:
        op.drop_index(idx, table_name="job_state")

    # Remove new columns from assets
    op.drop_column("assets", "tech")
    op.drop_index("ix_assets_target_type", table_name="assets")
    op.drop_index("ix_assets_target_created", table_name="assets")

    # Remove new index from alerts
    op.drop_index("ix_alerts_target_read", table_name="alerts")
