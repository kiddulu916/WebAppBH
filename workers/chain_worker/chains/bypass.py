# workers/chain_worker/chains/bypass.py
"""19 bypass chain templates."""
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
# 1. null_byte_extension_bypass_upload
# ---------------------------------------------------------------------------
@register_chain
class NullByteExtensionBypassUpload(BaseChainTemplate):
    name = "null_byte_extension_bypass_upload"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("null byte") + findings.vulns_by_title_contains("extension bypass")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["null_byte_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["null_byte_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_null_byte_filename", target="upload_endpoint", result="extension_check_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_malicious_file", target="upload_endpoint", result="file_stored_as_php", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="execute_uploaded_file", target="uploaded_path", result="code_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="shell.php%00.jpg bypasses extension whitelist", chain_name=self.name)


# ---------------------------------------------------------------------------
# 2. double_encoding_waf_bypass
# ---------------------------------------------------------------------------
@register_chain
class DoubleEncodingWafBypass(BaseChainTemplate):
    name = "double_encoding_waf_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("double encoding") + findings.vulns_by_title_contains("WAF")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["double_encoding_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["double_encoding_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="double_encode_payload", target="waf_protected_endpoint", result="waf_rule_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="deliver_payload_to_backend", target="backend_server", result="payload_decoded_and_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="%252e%252e%252f to bypass WAF path traversal rules", chain_name=self.name)


# ---------------------------------------------------------------------------
# 3. http2_downgrade_security_bypass
# ---------------------------------------------------------------------------
@register_chain
class Http2DowngradeSecurityBypass(BaseChainTemplate):
    name = "http2_downgrade_security_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("HTTP/2") + findings.vulns_by_title_contains("downgrade")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["http2_downgrade_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["http2_downgrade_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="force_http1_downgrade", target="proxy_endpoint", result="protocol_downgraded", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exploit_http1_weakness", target="backend_server", result="security_control_bypassed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Force HTTP/1.1 downgrade to bypass HTTP/2-only security headers", chain_name=self.name)


# ---------------------------------------------------------------------------
# 4. json_xml_interop_validation_bypass
# ---------------------------------------------------------------------------
@register_chain
class JsonXmlInteropValidationBypass(BaseChainTemplate):
    name = "json_xml_interop_validation_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        j = findings.vulns_by_title_contains("JSON")
        x = findings.vulns_by_title_contains("XML")
        m = [v for v in j if v in x]
        pd = findings.vulns_by_title_contains("parser differential")
        if not m and not pd:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["json_xml_interop_vulnerability"])
        combined = m + pd
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["interop_vuln_found"], matched_findings={"vuln_id": combined[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_xml_to_json_endpoint", target="api_endpoint", result="parser_accepts_wrong_format", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="inject_via_parser_diff", target="validation_layer", result="validation_bypassed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Send XML body with Content-Type: application/json to bypass JSON schema validation", chain_name=self.name)


# ---------------------------------------------------------------------------
# 5. ipv6_acl_bypass_internal
# ---------------------------------------------------------------------------
@register_chain
class Ipv6AclBypassInternal(BaseChainTemplate):
    name = "ipv6_acl_bypass_internal"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("IPv6") + findings.vulns_by_title_contains("ACL bypass")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["ipv6_acl_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ipv6_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="connect_via_ipv6", target="target_service", result="ipv4_acl_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_internal_service", target="internal_endpoint", result="internal_access_gained", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="curl -6 http://[::1]:8080/admin to bypass IPv4-only ACL", chain_name=self.name)


# ---------------------------------------------------------------------------
# 6. sni_mismatch_vhost_bypass
# ---------------------------------------------------------------------------
@register_chain
class SniMismatchVhostBypass(BaseChainTemplate):
    name = "sni_mismatch_vhost_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("SNI") + findings.vulns_by_title_contains("virtual host")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["sni_vhost_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["sni_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_mismatched_sni", target="tls_handshake", result="sni_host_mismatch_accepted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_hidden_vhost", target="internal_vhost", result="hidden_application_accessed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="TLS SNI=public.com but Host: internal.target.com", chain_name=self.name)


# ---------------------------------------------------------------------------
# 7. regex_redos_race_window
# ---------------------------------------------------------------------------
@register_chain
class RegexRedosRaceWindow(BaseChainTemplate):
    name = "regex_redos_race_window"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("ReDoS") + findings.vulns_by_title_contains("regex")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["redos_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["redos_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_redos_payload", target="regex_validation", result="regex_engine_stalled", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="race_during_stall", target="rate_limiter", result="rate_limit_bypassed_during_dos", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="aaaaaaaaaaaaaaaaaaaaaaaaaaaa! to stall regex, then race bypass", chain_name=self.name)


# ---------------------------------------------------------------------------
# 8. param_pollution_waf_bypass
# ---------------------------------------------------------------------------
@register_chain
class ParamPollutionWafBypass(BaseChainTemplate):
    name = "param_pollution_waf_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("parameter pollution") + findings.vulns_by_title_contains("HPP")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["hpp_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["hpp_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="duplicate_parameter", target="waf_protected_endpoint", result="waf_inspects_first_value", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="backend_uses_last_value", target="backend_server", result="malicious_value_processed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="?search=safe&search=<script>alert(1)</script>", chain_name=self.name)


# ---------------------------------------------------------------------------
# 9. unicode_encoding_filter_bypass
# ---------------------------------------------------------------------------
@register_chain
class UnicodeEncodingFilterBypass(BaseChainTemplate):
    name = "unicode_encoding_filter_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("unicode") + findings.vulns_by_title_contains("encoding bypass")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["unicode_bypass_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["unicode_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="encode_payload_unicode", target="input_filter", result="filter_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="deliver_normalized_payload", target="backend_normalizer", result="payload_executed_after_normalization", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", chain_name=self.name)


# ---------------------------------------------------------------------------
# 10. api_versioning_auth_bypass
# ---------------------------------------------------------------------------
@register_chain
class ApiVersioningAuthBypass(BaseChainTemplate):
    name = "api_versioning_auth_bypass"
    category = "bypass"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        av = findings.vulns_by_title_contains("API version")
        v1 = findings.vulns_by_title_contains("v1")
        bp = findings.vulns_by_title_contains("bypass")
        m = av + [v for v in v1 if v in bp]
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["api_versioning_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["api_version_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="discover_old_api_version", target="api_discovery", result="legacy_version_found", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_via_old_version", target="legacy_api", result="auth_check_missing_in_v1", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Change /api/v3/admin to /api/v1/admin (no auth in v1)", chain_name=self.name)


# ---------------------------------------------------------------------------
# 11. chunked_encoding_waf_evasion
# ---------------------------------------------------------------------------
@register_chain
class ChunkedEncodingWafEvasion(BaseChainTemplate):
    name = "chunked_encoding_waf_evasion"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("chunked") + findings.vulns_by_title_contains("WAF evasion")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["chunked_evasion_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["chunked_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="split_payload_into_chunks", target="waf_proxy", result="waf_fails_to_reassemble", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="backend_reassembles_payload", target="backend_server", result="full_payload_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Transfer-Encoding: chunked with payload split across chunks", chain_name=self.name)


# ---------------------------------------------------------------------------
# 12. multipart_boundary_parser_confusion
# ---------------------------------------------------------------------------
@register_chain
class MultipartBoundaryParserConfusion(BaseChainTemplate):
    name = "multipart_boundary_parser_confusion"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("multipart") + findings.vulns_by_title_contains("boundary")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["multipart_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["multipart_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_ambiguous_boundary", target="multipart_parser", result="parser_boundary_confused", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="inject_via_hidden_part", target="waf_bypass", result="hidden_payload_processed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Content-Type: multipart/form-data; boundary=abc; boundary=xyz", chain_name=self.name)


# ---------------------------------------------------------------------------
# 13. backslash_normalization_traversal
# ---------------------------------------------------------------------------
@register_chain
class BackslashNormalizationTraversal(BaseChainTemplate):
    name = "backslash_normalization_traversal"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("normalization") + findings.vulns_by_title_contains("backslash")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["normalization_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["normalization_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_backslash_path", target="path_handler", result="backslash_normalized_to_slash", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="traverse_directory", target="file_system", result="path_traversal_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="/static/..\\..\\..\\etc\\passwd normalized by backend", chain_name=self.name)


# ---------------------------------------------------------------------------
# 14. case_sensitivity_route_bypass
# ---------------------------------------------------------------------------
@register_chain
class CaseSensitivityRouteBypass(BaseChainTemplate):
    name = "case_sensitivity_route_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("case sensitiv") + findings.vulns_by_title_contains("route bypass")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["case_sensitivity_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["case_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="alter_url_case", target="protected_route", result="auth_middleware_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_protected_endpoint", target="case_insensitive_backend", result="unauthorized_access", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="/Admin instead of /admin to bypass case-sensitive middleware", chain_name=self.name)


# ---------------------------------------------------------------------------
# 15. comment_injection_parser_bypass
# ---------------------------------------------------------------------------
@register_chain
class CommentInjectionParserBypass(BaseChainTemplate):
    name = "comment_injection_parser_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("comment injection") + findings.vulns_by_title_contains("parser bypass")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["comment_injection_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["comment_injection_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_parser_comment", target="input_validator", result="comment_hides_payload", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="execute_hidden_payload", target="backend_parser", result="payload_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="SELECT/**/1/**/FROM/**/users to bypass keyword filter", chain_name=self.name)


# ---------------------------------------------------------------------------
# 16. deserialization_gadget_filter_bypass
# ---------------------------------------------------------------------------
@register_chain
class DeserializationGadgetFilterBypass(BaseChainTemplate):
    name = "deserialization_gadget_filter_bypass"
    category = "bypass"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        dg = findings.vulns_by_title_contains("deserialization")
        gd = findings.vulns_by_title_contains("gadget")
        fl = findings.vulns_by_title_contains("filter")
        m = [v for v in dg if v in gd] + [v for v in dg if v in fl]
        if not m and not dg:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["deserialization_gadget_vulnerability"])
        if m:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["gadget_filter_found"], matched_findings={"vuln_id": m[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["deserialization_found"], missing_preconditions=["gadget_chain_available"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="identify_allowed_classes", target="deserialization_filter", result="filter_rules_mapped", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="build_gadget_from_allowed", target="class_loader", result="gadget_chain_built", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="execute_gadget_chain", target="deserialization_endpoint", result="rce_via_filter_bypass", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Gadget chain using only allowed classes to bypass JEP-290 filter", chain_name=self.name)


# ---------------------------------------------------------------------------
# 17. content_length_zero_smuggling
# ---------------------------------------------------------------------------
@register_chain
class ContentLengthZeroSmuggling(BaseChainTemplate):
    name = "content_length_zero_smuggling"
    category = "bypass"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("content-length") + findings.vulns_by_title_contains("smuggling")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["cl_smuggling_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["cl_smuggling_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_cl_zero_with_body", target="front_proxy", result="proxy_ignores_body", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="backend_processes_body", target="backend_server", result="smuggled_request_processed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Content-Length: 0 with body containing smuggled request", chain_name=self.name)


# ---------------------------------------------------------------------------
# 18. browser_parser_diff_sanitizer_bypass
# ---------------------------------------------------------------------------
@register_chain
class BrowserParserDiffSanitizerBypass(BaseChainTemplate):
    name = "browser_parser_diff_sanitizer_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("sanitizer bypass") + findings.vulns_by_title_contains("browser parser")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["sanitizer_bypass_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["sanitizer_bypass_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_parser_differential", target="html_sanitizer", result="sanitizer_parses_differently", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_xss_in_browser", target="victim_browser", result="xss_via_parser_diff", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<noscript><img src=x onerror=alert(1)></noscript> parsed differently by sanitizer vs browser", chain_name=self.name)


# ---------------------------------------------------------------------------
# 19. graphql_batching_rate_limit_bypass
# ---------------------------------------------------------------------------
@register_chain
class GraphqlBatchingRateLimitBypass(BaseChainTemplate):
    name = "graphql_batching_rate_limit_bypass"
    category = "bypass"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        gql = findings.vulns_by_title_contains("GraphQL")
        rl = findings.vulns_by_title_contains("rate")
        m = [v for v in gql if v in rl]
        batch = findings.vulns_by_title_contains("batching")
        combined = m + batch
        if not combined:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["graphql_rate_limit_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["graphql_batch_found"], matched_findings={"vuln_id": combined[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_batched_query", target="graphql_endpoint", result="batch_accepted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="brute_force_via_batch", target="auth_mutation", result="rate_limit_bypassed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="[{query:'mutation{login(p:\"pass1\")}'},{query:'mutation{login(p:\"pass2\")}'},...x1000]", chain_name=self.name)
