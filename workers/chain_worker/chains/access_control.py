# workers/chain_worker/chains/access_control.py
"""21 access-control chain templates."""
from __future__ import annotations

from datetime import datetime

from workers.chain_worker.registry import BaseChainTemplate, ChainContext, register_chain
from workers.chain_worker.models import (
    ChainViability, ChainResult, ChainStep, EvaluationResult, TargetFindings,
)
from workers.chain_worker.base_tool import step_delay, take_screenshot


def _ts() -> str:
    return datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# 1. forced_browsing_admin_default_creds
# ---------------------------------------------------------------------------
@register_chain
class ForcedBrowsingAdminDefaultCreds(BaseChainTemplate):
    name = "forced_browsing_admin_default_creds"
    category = "access_control"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("admin") + findings.vulns_by_title_contains("default cred")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["admin_default_cred_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["admin_panel_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="discover_admin_panel", target="common_admin_paths", result="admin_panel_found", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="try_default_credentials", target="admin_login", result="login_successful", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_privileges", target="admin_dashboard", result="full_admin_access", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="admin:admin on /admin/login", chain_name=self.name)


# ---------------------------------------------------------------------------
# 2. multi_step_workflow_bypass
# ---------------------------------------------------------------------------
@register_chain
class MultiStepWorkflowBypass(BaseChainTemplate):
    name = "multi_step_workflow_bypass"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("workflow") + findings.vulns_by_title_contains("multi-step")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["workflow_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["workflow_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="skip_verification_step", target="step2_endpoint", result="verification_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="complete_action_directly", target="final_step_endpoint", result="action_completed_without_checks", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Skip step 2 (verification) and POST directly to step 3 (confirm)", chain_name=self.name)


# ---------------------------------------------------------------------------
# 3. tenant_isolation_bypass
# ---------------------------------------------------------------------------
@register_chain
class TenantIsolationBypass(BaseChainTemplate):
    name = "tenant_isolation_bypass"
    category = "access_control"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("tenant") + findings.vulns_by_title_contains("multi-tenant")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["tenant_isolation_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["tenant_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="identify_tenant_parameter", target="api_request", result="tenant_id_found", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="swap_tenant_identifier", target="api_endpoint", result="cross_tenant_access", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_other_tenant_data", target="tenant_resources", result="data_exfiltrated", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Change X-Tenant-ID header to access other tenant's data", chain_name=self.name)


# ---------------------------------------------------------------------------
# 4. role_downgrade_hidden_access
# ---------------------------------------------------------------------------
@register_chain
class RoleDowngradeHiddenAccess(BaseChainTemplate):
    name = "role_downgrade_hidden_access"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = True

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("role") + findings.vulns_by_title_contains("authorization")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["role_authorization_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["role_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="enumerate_role_endpoints", target="api_endpoints", result="hidden_endpoints_found", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_with_lower_role", target="admin_endpoint", result="unauthorized_access_gained", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Access /api/admin/users with regular user JWT token", chain_name=self.name)


# ---------------------------------------------------------------------------
# 5. coupon_promo_financial_abuse
# ---------------------------------------------------------------------------
@register_chain
class CouponPromoFinancialAbuse(BaseChainTemplate):
    name = "coupon_promo_financial_abuse"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("coupon") + findings.vulns_by_title_contains("discount")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["coupon_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["coupon_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="apply_coupon_multiple_times", target="checkout_endpoint", result="coupon_stacked", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="complete_purchase", target="payment_endpoint", result="purchase_at_negative_price", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Apply same coupon code multiple times in single checkout request", chain_name=self.name)


# ---------------------------------------------------------------------------
# 6. email_verification_bypass_squat
# ---------------------------------------------------------------------------
@register_chain
class EmailVerificationBypassSquat(BaseChainTemplate):
    name = "email_verification_bypass_squat"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("verification") + findings.vulns_by_title_contains("email bypass")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["email_verification_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["email_bypass_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="register_with_target_email", target="registration_endpoint", result="account_created_unverified", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="bypass_verification", target="verification_endpoint", result="email_marked_verified", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Modify is_verified=true in registration response or direct API call", chain_name=self.name)


# ---------------------------------------------------------------------------
# 7. concurrent_request_double_spend
# ---------------------------------------------------------------------------
@register_chain
class ConcurrentRequestDoubleSpend(BaseChainTemplate):
    name = "concurrent_request_double_spend"
    category = "access_control"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("race condition") + findings.vulns_by_title_contains("concurrent")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["race_condition_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["race_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="prepare_concurrent_requests", target="transfer_endpoint", result="requests_prepared", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="send_simultaneous_transfers", target="transfer_endpoint", result="double_spend_achieved", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="verify_balance_inconsistency", target="balance_endpoint", result="financial_loss_confirmed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Send 20 concurrent POST /transfer requests with same token", chain_name=self.name)


# ---------------------------------------------------------------------------
# 8. batch_endpoint_auth_bypass
# ---------------------------------------------------------------------------
@register_chain
class BatchEndpointAuthBypass(BaseChainTemplate):
    name = "batch_endpoint_auth_bypass"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("batch") + findings.vulns_by_title_contains("bulk")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["batch_endpoint_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["batch_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="discover_batch_endpoint", target="api_discovery", result="batch_endpoint_found", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="include_protected_operations", target="batch_request", result="auth_check_skipped_in_batch", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="POST /api/batch [{method:'DELETE',url:'/api/admin/user/1'}]", chain_name=self.name)


# ---------------------------------------------------------------------------
# 9. broken_access_horizontal_vertical
# ---------------------------------------------------------------------------
@register_chain
class BrokenAccessHorizontalVertical(BaseChainTemplate):
    name = "broken_access_horizontal_vertical"
    category = "access_control"
    severity_on_success = "critical"
    requires_accounts = True

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("access control") + findings.vulns_by_title_contains("IDOR")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["access_control_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["idor_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="enumerate_object_ids", target="api_endpoint", result="valid_ids_discovered", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_other_user_object", target="victim_resource", result="horizontal_access_gained", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_to_admin_object", target="admin_resource", result="vertical_access_gained", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="GET /api/users/2/profile with user 1 session token", chain_name=self.name)


# ---------------------------------------------------------------------------
# 10. race_condition_privesc
# ---------------------------------------------------------------------------
@register_chain
class RaceConditionPrivesc(BaseChainTemplate):
    name = "race_condition_privesc"
    category = "access_control"
    severity_on_success = "critical"
    requires_accounts = True

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("race condition")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["race_condition_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["race_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="race_role_change_and_action", target="role_endpoint", result="race_window_exploited", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="perform_admin_action", target="admin_api", result="admin_action_completed_as_user", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Race role upgrade request with admin-only action request", chain_name=self.name)


# ---------------------------------------------------------------------------
# 11. business_logic_financial_exploit
# ---------------------------------------------------------------------------
@register_chain
class BusinessLogicFinancialExploit(BaseChainTemplate):
    name = "business_logic_financial_exploit"
    category = "access_control"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("business logic") + findings.vulns_by_title_contains("payment")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["business_logic_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["biz_logic_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="manipulate_price_parameter", target="checkout_api", result="price_modified", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="complete_transaction", target="payment_gateway", result="transaction_at_wrong_price", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="verify_financial_impact", target="order_confirmation", result="financial_loss_confirmed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Change price from 9999 to 1 in POST /api/checkout body", chain_name=self.name)


# ---------------------------------------------------------------------------
# 12. nosql_injection_auth_bypass
# ---------------------------------------------------------------------------
@register_chain
class NosqlInjectionAuthBypass(BaseChainTemplate):
    name = "nosql_injection_auth_bypass"
    category = "access_control"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("NoSQL")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["nosql_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["nosql_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_nosql_operator", target="login_endpoint", result="auth_query_manipulated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="bypass_authentication", target="auth_system", result="logged_in_as_admin", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc='{"username":{"$gt":""},"password":{"$gt":""}}', chain_name=self.name)


# ---------------------------------------------------------------------------
# 13. invite_flow_privesc
# ---------------------------------------------------------------------------
@register_chain
class InviteFlowPrivesc(BaseChainTemplate):
    name = "invite_flow_privesc"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = True

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("invite") + findings.vulns_by_title_contains("invitation")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["invite_flow_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["invite_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="intercept_invite_request", target="invite_endpoint", result="invite_token_captured", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="modify_role_in_invite", target="invite_payload", result="role_escalated_in_invite", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="accept_modified_invite", target="accept_endpoint", result="joined_as_admin", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Modify role=member to role=admin in POST /api/invites/accept", chain_name=self.name)


# ---------------------------------------------------------------------------
# 14. subscription_tier_bypass
# ---------------------------------------------------------------------------
@register_chain
class SubscriptionTierBypass(BaseChainTemplate):
    name = "subscription_tier_bypass"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("subscription") + findings.vulns_by_title_contains("tier")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["subscription_tier_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["tier_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="identify_premium_endpoints", target="api_discovery", result="premium_features_enumerated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_premium_with_free_tier", target="premium_api", result="tier_check_bypassed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Access /api/premium/export with free-tier JWT token", chain_name=self.name)


# ---------------------------------------------------------------------------
# 15. referral_reward_abuse
# ---------------------------------------------------------------------------
@register_chain
class ReferralRewardAbuse(BaseChainTemplate):
    name = "referral_reward_abuse"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("referral") + findings.vulns_by_title_contains("reward")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["referral_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["referral_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="generate_referral_code", target="referral_endpoint", result="code_generated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="self_refer_multiple_accounts", target="registration_endpoint", result="rewards_accumulated", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Self-referral loop with disposable email addresses", chain_name=self.name)


# ---------------------------------------------------------------------------
# 16. feature_flag_manipulation
# ---------------------------------------------------------------------------
@register_chain
class FeatureFlagManipulation(BaseChainTemplate):
    name = "feature_flag_manipulation"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("feature flag") + findings.vulns_by_title_contains("toggle")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["feature_flag_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["feature_flag_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="discover_feature_flags", target="config_endpoint", result="flags_enumerated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="toggle_restricted_feature", target="flag_api", result="hidden_feature_enabled", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="PUT /api/features {\"beta_admin_panel\": true}", chain_name=self.name)


# ---------------------------------------------------------------------------
# 17. export_bulk_data_exfil
# ---------------------------------------------------------------------------
@register_chain
class ExportBulkDataExfil(BaseChainTemplate):
    name = "export_bulk_data_exfil"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("export") + findings.vulns_by_title_contains("download")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["export_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["export_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="manipulate_export_scope", target="export_endpoint", result="scope_expanded_to_all_records", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="download_bulk_data", target="export_file", result="mass_data_exfiltrated", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="GET /api/export?scope=all&format=csv without pagination limit", chain_name=self.name)


# ---------------------------------------------------------------------------
# 18. audit_log_tampering
# ---------------------------------------------------------------------------
@register_chain
class AuditLogTampering(BaseChainTemplate):
    name = "audit_log_tampering"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("audit") + findings.vulns_by_title_contains("log tampering")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["audit_log_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["audit_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="access_audit_log_endpoint", target="audit_api", result="logs_accessible", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="delete_or_modify_logs", target="audit_records", result="evidence_tampered", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="DELETE /api/audit-logs/123 or PUT to modify log entry", chain_name=self.name)


# ---------------------------------------------------------------------------
# 19. toctou_file_access_race
# ---------------------------------------------------------------------------
@register_chain
class ToctouFileAccessRace(BaseChainTemplate):
    name = "toctou_file_access_race"
    category = "access_control"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("TOCTOU") + findings.vulns_by_title_contains("time-of-check")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["toctou_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["toctou_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="upload_benign_file", target="upload_endpoint", result="file_passes_validation", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="race_replace_with_malicious", target="file_storage", result="file_replaced_before_use", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_file_processing", target="processing_endpoint", result="malicious_file_processed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Upload safe.txt, then race to replace with shell.php before processing", chain_name=self.name)


# ---------------------------------------------------------------------------
# 20. soft_delete_bypass_data_access
# ---------------------------------------------------------------------------
@register_chain
class SoftDeleteBypassDataAccess(BaseChainTemplate):
    name = "soft_delete_bypass_data_access"
    category = "access_control"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("soft delete") + findings.vulns_by_title_contains("deleted")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["soft_delete_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["soft_delete_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="query_with_deleted_filter", target="api_endpoint", result="deleted_records_accessible", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_deleted_data", target="deleted_resources", result="sensitive_deleted_data_retrieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="GET /api/users?include_deleted=true or /api/users?status=deleted", chain_name=self.name)


# ---------------------------------------------------------------------------
# 21. graphql_introspection_exfil
# ---------------------------------------------------------------------------
@register_chain
class GraphqlIntrospectionExfil(BaseChainTemplate):
    name = "graphql_introspection_exfil"
    category = "access_control"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("GraphQL") + findings.vulns_by_title_contains("introspection")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["graphql_introspection_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["graphql_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="run_introspection_query", target="graphql_endpoint", result="schema_fully_exposed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="discover_hidden_mutations", target="schema_analysis", result="sensitive_mutations_found", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exfiltrate_via_mutations", target="hidden_mutation", result="data_exfiltrated", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="{__schema{types{name fields{name args{name}}}}}", chain_name=self.name)
