"""Tests for the payload mutation engine (Task 6).

Covers:
- Base mutation strategies per vuln type (XSS, SQLi, SSRF, cmd injection, XXE, SSTI, path traversal)
- InjectionContext dispatch — only context-valid mutations applied
- WAF fingerprinting from HTTP response metadata
- Chained mutations (2-3 depth)
- MutationOutcome DB model
- Payload corpus has entries for every supported vuln type
"""

import pytest
from unittest.mock import MagicMock

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Base mutation strategies
# ---------------------------------------------------------------------------

class TestMutator:
    def test_xss_mutations_produce_variants(self):
        from workers.sandbox_worker.mutator import mutate

        payload = "<script>alert(1)</script>"
        variants = mutate(payload, vuln_type="xss")
        assert len(variants) > 0
        assert all(isinstance(v, str) for v in variants)
        assert payload not in variants  # original excluded

    def test_sqli_mutations_produce_variants(self):
        from workers.sandbox_worker.mutator import mutate

        payload = "' OR '1'='1"
        variants = mutate(payload, vuln_type="sqli")
        assert len(variants) > 0

    def test_ssrf_mutations_produce_variants(self):
        from workers.sandbox_worker.mutator import mutate

        payload = "http://169.254.169.254/latest/meta-data/"
        variants = mutate(payload, vuln_type="ssrf")
        assert len(variants) > 0

    def test_command_injection_mutations_produce_variants(self):
        from workers.sandbox_worker.mutator import mutate

        payload = "; cat /etc/passwd"
        variants = mutate(payload, vuln_type="command_injection")
        assert len(variants) > 0

    def test_xxe_mutations_produce_variants(self):
        from workers.sandbox_worker.mutator import mutate

        payload = '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
        variants = mutate(payload, vuln_type="xxe")
        assert len(variants) > 0

    def test_template_injection_mutations_produce_variants(self):
        from workers.sandbox_worker.mutator import mutate

        payload = "{{7*7}}"
        variants = mutate(payload, vuln_type="template_injection")
        assert len(variants) > 0

    def test_path_traversal_mutations_produce_variants(self):
        from workers.sandbox_worker.mutator import mutate

        payload = "../../../etc/passwd"
        variants = mutate(payload, vuln_type="path_traversal")
        assert len(variants) > 0

    def test_unknown_vuln_type_returns_empty(self):
        from workers.sandbox_worker.mutator import mutate

        variants = mutate("test", vuln_type="nonexistent")
        assert variants == []


# ---------------------------------------------------------------------------
# InjectionContext
# ---------------------------------------------------------------------------

class TestContext:
    def test_injection_context_enum_values(self):
        from workers.sandbox_worker.context import InjectionContext

        assert InjectionContext.HTML_TAG.value == "html_tag"
        assert InjectionContext.JS_STRING.value == "js_string"
        assert InjectionContext.SQL_STRING.value == "sql_string"
        assert InjectionContext.URL_PARAM.value == "url_param"

    def test_context_aware_mutation_filters_strategies(self):
        """html_entity encoding should apply in HTML_TAG but not JS_STRING."""
        from workers.sandbox_worker.context import InjectionContext
        from workers.sandbox_worker.mutator import mutate

        payload = "<script>alert(1)</script>"
        html_variants = mutate(payload, vuln_type="xss", context=InjectionContext.HTML_TAG)
        js_variants = mutate(payload, vuln_type="xss", context=InjectionContext.JS_STRING)

        # HTML context should produce more or different variants than JS context
        assert len(html_variants) > 0
        assert len(js_variants) > 0
        # The sets shouldn't be identical (different strategies valid per context)
        assert set(html_variants) != set(js_variants)


# ---------------------------------------------------------------------------
# WAF fingerprinting
# ---------------------------------------------------------------------------

class TestWAFFingerprint:
    def test_cloudflare_detected(self):
        from workers.sandbox_worker.waf_fingerprint import fingerprint_waf

        result = fingerprint_waf(
            headers={"server": "cloudflare", "cf-ray": "abc123"},
            body="",
            status_code=403,
        )
        assert result == "cloudflare"

    def test_akamai_detected(self):
        from workers.sandbox_worker.waf_fingerprint import fingerprint_waf

        result = fingerprint_waf(
            headers={"server": "AkamaiGHost"},
            body="Reference #18.abc123.1234567890",
            status_code=403,
        )
        assert result == "akamai"

    def test_modsecurity_detected(self):
        from workers.sandbox_worker.waf_fingerprint import fingerprint_waf

        result = fingerprint_waf(
            headers={},
            body="ModSecurity Action",
            status_code=406,
        )
        assert result == "modsecurity"

    def test_no_waf_returns_none(self):
        from workers.sandbox_worker.waf_fingerprint import fingerprint_waf

        result = fingerprint_waf(
            headers={"server": "nginx"},
            body="Hello world",
            status_code=200,
        )
        assert result is None

    def test_imperva_detected(self):
        from workers.sandbox_worker.waf_fingerprint import fingerprint_waf

        result = fingerprint_waf(
            headers={"x-cdn": "Incapsula"},
            body="",
            status_code=403,
        )
        assert result == "imperva"


# ---------------------------------------------------------------------------
# Chained mutations
# ---------------------------------------------------------------------------

class TestChaining:
    def test_chain_two_mutations(self):
        from workers.sandbox_worker.chaining import chain_mutate

        payload = "<script>alert(1)</script>"
        variants = chain_mutate(payload, vuln_type="xss", depth=2)
        assert len(variants) > 0
        # Chained variants should differ from single-pass variants
        from workers.sandbox_worker.mutator import mutate
        single = set(mutate(payload, vuln_type="xss"))
        chained = set(variants)
        # At least some chained results should be different
        assert chained - single

    def test_chain_respects_max_depth(self):
        from workers.sandbox_worker.chaining import chain_mutate

        payload = "' OR '1'='1"
        variants = chain_mutate(payload, vuln_type="sqli", depth=3, max_variants=10)
        assert len(variants) <= 10

    def test_chain_depth_one_equals_single_mutate(self):
        from workers.sandbox_worker.chaining import chain_mutate
        from workers.sandbox_worker.mutator import mutate

        payload = "{{7*7}}"
        single = sorted(mutate(payload, vuln_type="template_injection"))
        chained = sorted(chain_mutate(payload, vuln_type="template_injection", depth=1))
        assert single == chained


# ---------------------------------------------------------------------------
# MutationOutcome DB model
# ---------------------------------------------------------------------------

class TestMutationOutcomeModel:
    async def test_model_exists_and_has_columns(self, db):
        from lib_webbh.database import MutationOutcome

        assert MutationOutcome.__tablename__ == "mutation_outcomes"
        cols = {c.name for c in MutationOutcome.__table__.columns}
        assert {
            "vuln_type",
            "waf_profile",
            "mutation_chain",
            "context",
            "bypassed",
            "total_attempts",
            "successful_attempts",
        }.issubset(cols)


# ---------------------------------------------------------------------------
# Payload corpus
# ---------------------------------------------------------------------------

class TestPayloadCorpus:
    def test_corpus_has_all_vuln_types(self):
        from workers.sandbox_worker.payload_corpus import CORPUS, SUPPORTED_VULN_TYPES

        for vt in SUPPORTED_VULN_TYPES:
            matching = [k for k in CORPUS if k[0] == vt]
            assert len(matching) > 0, f"No corpus entries for vuln_type={vt}"

    def test_corpus_entries_are_nonempty_strings(self):
        from workers.sandbox_worker.payload_corpus import CORPUS

        for key, payloads in CORPUS.items():
            assert len(payloads) > 0, f"Empty payload list for {key}"
            assert all(isinstance(p, str) and p.strip() for p in payloads)
