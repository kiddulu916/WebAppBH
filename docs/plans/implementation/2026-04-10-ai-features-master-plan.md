# AI Features Master Implementation Plan (Revised)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

> **Revision notes (2026-04-10):** This plan supersedes `archive/2026-04-08-ai-features-master-plan.md`. Key changes:
> - **Task 0:** Anthropic SDK replaced with self-hosted Ollama container running Qwen3 14B. All LLM calls are local. Prompt templates adapted from PentestGPT.
> - **Task 1:** Report formats expanded from 2 to 5 (added Intigriti, YesWeHack, generic markdown).
> - **Task 2:** Analysis types expanded from 5 to 10 (added bounty estimate, duplicate likelihood, OWASP/CWE mapping, report-readiness, asset criticality).
> - **Task 3:** Platform API coverage expanded from 2 to 4 (added Intigriti, YesWeHack).
> - **Task 4:** Unchanged.
> - **Task 5:** Added 6 quality constraints on LLM-proposed chains.
> - **Task 6:** WASM/QuickJS sandbox dropped. Now a pure-Python multi-vuln mutation engine with context-aware mutations, chaining, WAF fingerprinting, a success feedback loop, worker integration, and a seed payload corpus.

**Goal:** Add 6 AI-powered features to the WebAppBH framework: LLM-powered report writing, vulnerability reasoning, bug bounty platform integration, adaptive scan intelligence, autonomous chain discovery, and a payload mutation engine. All LLM inference runs locally — no external API dependencies.

**Architecture:** Each feature is built as an independent module following existing patterns (workers listen on Redis streams, DB models in `shared/lib_webbh/database.py`, orchestrator endpoints in `orchestrator/main.py`). Features #2, #1, and #5 share a common local-LLM client wrapper built in Task 0. Features are built sequentially — each one is fully tested before moving to the next.

**Tech Stack:** Python 3.11+, `httpx` (LLM + platform APIs), Ollama (self-hosted LLM runtime), Qwen3 14B (default model), SQLAlchemy async, FastAPI, Redis Streams.

---

## Feature Build Order

| Order | Feature | ID | New Files | Modified Files |
|-------|---------|-----|-----------|----------------|
| 0 | Local LLM Client + Ollama Container | — | 4 | 3 |
| 1 | Auto-Report Writer (5 formats) | #2 | 4 | 4 |
| 2 | Vulnerability Reasoning Engine (10 analyses) | #1 | 5 | 4 |
| 3 | Bug Bounty Platform API Integration (4 platforms) | #11 | 6 | 3 |
| 4 | Adaptive Scan Intelligence | #4 | 3 | 5 |
| 5 | Autonomous Chain Discovery (6 constraints) | #5 | 3 | 3 |
| 6 | Payload Mutation Engine (no WASM) | #9 | 8 | 4 |

---

## Task 0: Local LLM Client + Ollama Container

All LLM-dependent features (#2, #1, #5) share a thin async wrapper around Ollama's HTTP API. Model serving runs in a dedicated `ollama` container defined in `docker-compose.yml`. No external API keys, no third-party SDKs.

**Files:**
- Create: `shared/lib_webbh/llm_client.py`
- Create: `shared/lib_webbh/prompts/__init__.py`
- Create: `shared/lib_webbh/prompts/pentestgpt_adapted.py` (prompt templates adapted from PentestGPT)
- Create: `docker/Dockerfile.ollama` (optional; can also use upstream image directly)
- Modify: `shared/lib_webbh/__init__.py` (export new symbols)
- Modify: `docker-compose.yml` (add `ollama` service)
- Modify: `shared/lib_webbh/setup.cfg` or `pyproject.toml` (add `httpx` if not already present)
- Test: `tests/test_llm_client.py`

### PentestGPT Prompt Attribution

Task 0 introduces `shared/lib_webbh/prompts/pentestgpt_adapted.py`, which contains prompt templates adapted from [PentestGPT](https://github.com/GreyDGL/PentestGPT) (MIT License). We are **not** running PentestGPT itself — we borrow and adapt its domain-expert system prompts for report writing (Task 1), vulnerability reasoning (Task 2), and chain discovery (Task 5). Each adapted prompt includes an attribution comment in the source file.

### Ollama Container Configuration

Add to `docker-compose.yml`:

```yaml
ollama:
  image: ollama/ollama:latest
  container_name: webappbh-ollama
  ports:
    - "11434:11434"
  volumes:
    - ollama-models:/root/.ollama
  environment:
    - OLLAMA_KEEP_ALIVE=24h
    - OLLAMA_NUM_PARALLEL=4
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: all
            capabilities: [gpu]
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
    interval: 30s
    timeout: 10s
    retries: 3
```

Add volume:
```yaml
volumes:
  ollama-models:
```

> **GPU requirement:** The service reserves all NVIDIA GPUs. On machines without GPU, remove the `deploy.resources.reservations.devices` block — Ollama will fall back to CPU inference (much slower). GPU is opt-out, not opt-in, because Qwen3 14B on CPU is too slow for batch reasoning.

### Initial Model Pull

On first run, the Qwen3 14B model must be pulled into the Ollama container. Document this in `README.md` (or a bootstrap script):

```bash
docker compose exec ollama ollama pull qwen3:14b
```

### Step 1: Write the failing test for LLM client

```python
# tests/test_llm_client.py
"""Tests for the local LLM client wrapper (Ollama backend)."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

pytestmark = pytest.mark.anyio


async def test_generate_text_returns_response():
    """LLMClient.generate() returns the text + token counts from Ollama."""
    mock_payload = {
        "response": "Hello world",
        "prompt_eval_count": 10,
        "eval_count": 5,
        "done": True,
    }
    mock_http_response = MagicMock()
    mock_http_response.json = MagicMock(return_value=mock_payload)
    mock_http_response.raise_for_status = MagicMock()

    with patch("lib_webbh.llm_client.httpx.AsyncClient") as MockClient:
        instance = MockClient.return_value.__aenter__.return_value
        instance.post = AsyncMock(return_value=mock_http_response)

        from lib_webbh.llm_client import LLMClient
        client = LLMClient(base_url="http://ollama:11434", model="qwen3:14b")
        result = await client.generate("Say hello")

        assert result.text == "Hello world"
        assert result.input_tokens == 10
        assert result.output_tokens == 5


async def test_generate_with_system_prompt():
    """System prompt is passed through to Ollama."""
    mock_payload = {"response": "ok", "prompt_eval_count": 5, "eval_count": 2, "done": True}
    mock_http_response = MagicMock()
    mock_http_response.json = MagicMock(return_value=mock_payload)
    mock_http_response.raise_for_status = MagicMock()

    with patch("lib_webbh.llm_client.httpx.AsyncClient") as MockClient:
        instance = MockClient.return_value.__aenter__.return_value
        instance.post = AsyncMock(return_value=mock_http_response)

        from lib_webbh.llm_client import LLMClient
        client = LLMClient()
        await client.generate("Analyze this vuln", system="You are a security analyst.")

        call_kwargs = instance.post.call_args
        body = call_kwargs.kwargs["json"]
        assert body["system"] == "You are a security analyst."


async def test_generate_json_mode():
    """JSON mode sets format=json in the Ollama request."""
    mock_payload = {"response": '{"ok": true}', "prompt_eval_count": 5, "eval_count": 2, "done": True}
    mock_http_response = MagicMock()
    mock_http_response.json = MagicMock(return_value=mock_payload)
    mock_http_response.raise_for_status = MagicMock()

    with patch("lib_webbh.llm_client.httpx.AsyncClient") as MockClient:
        instance = MockClient.return_value.__aenter__.return_value
        instance.post = AsyncMock(return_value=mock_http_response)

        from lib_webbh.llm_client import LLMClient
        client = LLMClient()
        result = await client.generate("Produce JSON", json_mode=True)

        body = instance.post.call_args.kwargs["json"]
        assert body["format"] == "json"
        assert result.text == '{"ok": true}'


async def test_client_uses_env_base_url_and_model():
    """Env vars override defaults: LLM_BASE_URL, LLM_MODEL."""
    with patch.dict("os.environ", {"LLM_BASE_URL": "http://custom:1234", "LLM_MODEL": "qwen3:8b"}):
        from lib_webbh.llm_client import LLMClient
        client = LLMClient()
        assert client._base_url == "http://custom:1234"
        assert client._model == "qwen3:8b"
```

### Step 2: Run test to verify it fails

Run: `pytest tests/test_llm_client.py -v`
Expected: FAIL with ImportError (module doesn't exist yet)

### Step 3: Implement the LLM client

```python
# shared/lib_webbh/llm_client.py
"""Thin async wrapper around Ollama's HTTP API for all LLM-dependent features."""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


@dataclass
class LLMResponse:
    """Normalized response from the LLM."""
    text: str
    input_tokens: int
    output_tokens: int


# Defaults — overridable per-call or via env vars.
DEFAULT_BASE_URL = os.environ.get("LLM_BASE_URL", "http://ollama:11434")
DEFAULT_MODEL = os.environ.get("LLM_MODEL", "qwen3:14b")
DEFAULT_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "4096"))
DEFAULT_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "600.0"))  # Large: batch reasoning can be slow


class LLMClient:
    """Async LLM client talking to a local Ollama server."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ):
        self._base_url = base_url or DEFAULT_BASE_URL
        self._model = model or DEFAULT_MODEL
        self._timeout = timeout or DEFAULT_TIMEOUT

    async def generate(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int | None = None,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Send a single prompt to Ollama and return the response text + token counts."""
        body: dict = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens or DEFAULT_MAX_TOKENS,
            },
        }
        if system:
            body["system"] = system
        if json_mode:
            body["format"] = "json"

        async with httpx.AsyncClient(timeout=self._timeout) as http:
            response = await http.post(f"{self._base_url}/api/generate", json=body)
            response.raise_for_status()
            data = response.json()

        return LLMResponse(
            text=data.get("response", ""),
            input_tokens=int(data.get("prompt_eval_count", 0)),
            output_tokens=int(data.get("eval_count", 0)),
        )
```

### Step 4: Create prompts package + PentestGPT-adapted module

```python
# shared/lib_webbh/prompts/__init__.py
"""Prompt templates for LLM-dependent features."""
```

```python
# shared/lib_webbh/prompts/pentestgpt_adapted.py
"""
Prompt templates adapted from PentestGPT (https://github.com/GreyDGL/PentestGPT, MIT License).

These adaptations provide pentest domain expertise for:
- Vulnerability reasoning (Task 2)
- Chain discovery (Task 5)
- Report writing (Task 1)

We are not running PentestGPT; we borrow and adapt its system prompts. Each
constant below notes the original PentestGPT module it was adapted from.
"""
from __future__ import annotations

# Adapted from PentestGPT's reasoning module system prompt.
REASONING_SYSTEM = """\
You are a senior penetration tester and security researcher analyzing vulnerability
findings from automated scanners. Your job is to produce actionable intelligence:

- Verify whether findings are likely real or false positives
- Assess real-world exploitability, not theoretical CVSS
- Identify exploit chains between findings
- Recommend concrete next manual testing steps

Be rigorous. Do not invent evidence. Only reason about data explicitly provided.
When unsure, say so explicitly and lower your confidence score.
"""

# Adapted from PentestGPT's generation module, for bug bounty report prose.
REPORT_WRITER_SYSTEM = """\
You are an expert bug bounty report writer. You write clear, concise, persuasive
vulnerability reports that maximize the chance of acceptance and fair payout on
bug bounty platforms.

Rules:
- Write in professional security researcher tone
- Include a clear, descriptive title
- Describe impact in business terms, not just technical terms
- Provide step-by-step reproduction that a triager can follow in under 5 minutes
- Include remediation advice that is specific and actionable
- Use markdown formatting appropriate for the target platform
- Do NOT fabricate evidence — only reference data provided in the findings
- If PoC data is provided, include it verbatim in a code block
"""

# Adapted from PentestGPT's reasoning module, for exploit chain hypothesis.
CHAIN_DISCOVERY_SYSTEM = """\
You are a senior offensive security researcher specializing in vulnerability chaining.
Given a set of findings for a single target, propose novel exploit chains that combine
multiple vulnerabilities for greater impact than any single finding alone.

Hard constraints:
- Only chain findings with evidence_confidence >= 0.7
- Every chain must include at least one Medium-severity-or-higher vulnerability
- Chains must be 2-4 steps, no longer
- Each chain must state the concrete goal (e.g., account takeover, data exfiltration, RCE)
- Never invent findings; only reference vulnerability IDs explicitly provided
- Reject chains where >80% of the steps overlap with templates already listed
- Rate your confidence 0.0-1.0 for each proposed chain
"""
```

### Step 5: Export from lib_webbh

Add to `shared/lib_webbh/__init__.py`:
```python
from lib_webbh.llm_client import LLMClient, LLMResponse
```

### Step 6: Add httpx dependency

Ensure `httpx>=0.27.0` is in the shared library's dependencies.

### Step 7: Run tests to verify they pass

Run: `pytest tests/test_llm_client.py -v`
Expected: All 4 tests PASS

### Step 8: Manual smoke test (optional but recommended)

```bash
docker compose up ollama
docker compose exec ollama ollama pull qwen3:14b
python -c "import asyncio; from lib_webbh.llm_client import LLMClient; \
  print(asyncio.run(LLMClient().generate('Say hi in 3 words')).text)"
```

### Step 9: Commit

```bash
git add shared/lib_webbh/llm_client.py shared/lib_webbh/prompts/ tests/test_llm_client.py \
  shared/lib_webbh/__init__.py docker-compose.yml
git commit -m "feat(llm): add local Ollama LLM client wrapper with Qwen3 14B default"
```

---

## Task 1: Auto-Report Writer (#2) — LLM-Powered Report Generation (5 Platforms)

Extends the existing reporting pipeline with an LLM renderer that generates persuasive, platform-ready bug bounty reports for **HackerOne, Bugcrowd, Intigriti, YesWeHack,** and a **generic markdown** format.

**Files:**
- Create: `shared/lib_webbh/prompts/report_writer.py`
- Create: `workers/reporting_worker/renderers/llm_renderer.py`
- Create: `tests/test_llm_report_writer.py`
- Modify: `workers/reporting_worker/pipeline.py` (add LLM formats to FORMAT_RENDERERS)
- Modify: `orchestrator/main.py` (add llm formats to ReportCreate Literal)

### Supported Formats

| Format key | Platform | Notes |
|------------|----------|-------|
| `llm_hackerone` | HackerOne | Uses `## Summary`, `## Steps to Reproduce`, `## Impact`, `## Remediation`; includes CVSS |
| `llm_bugcrowd` | Bugcrowd | Uses Overview, PoC, Impact, Fix Recommendation; VRT category names where known |
| `llm_intigriti` | Intigriti | Structured description, PoC, impact, reproduction steps; Intigriti taxonomy tags |
| `llm_yeswehack` | YesWeHack | Summary, Vulnerability Type, Description, Reproduction, Impact, Fix; CVSS vector |
| `llm_markdown` | Generic | Clean markdown for self-hosted programs, email submissions, or internal use |

### Prompt Builder

```python
# shared/lib_webbh/prompts/report_writer.py
"""Prompt templates for LLM-powered report generation (5 platforms)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from lib_webbh.prompts.pentestgpt_adapted import REPORT_WRITER_SYSTEM as SYSTEM_PROMPT

if TYPE_CHECKING:
    from workers.reporting_worker.deduplicator import ReportData


PLATFORM_GUIDANCE = {
    "hackerone": (
        "Format for HackerOne: use ## headers, include a Summary, "
        "## Steps to Reproduce (numbered), ## Impact section, "
        "and ## Remediation. Reference CVSS score."
    ),
    "bugcrowd": (
        "Format for Bugcrowd: use clear headers, include Overview, "
        "Proof of Concept (with request/response), Impact, and Fix Recommendation. "
        "Use Bugcrowd VRT category names when possible."
    ),
    "intigriti": (
        "Format for Intigriti: include a Description, Proof of Concept, "
        "Steps to Reproduce, Impact, and Recommendation. Reference the "
        "Intigriti taxonomy category (e.g., 'Cross-site Scripting (Reflected)')."
    ),
    "yeswehack": (
        "Format for YesWeHack: include Summary, Vulnerability Type, "
        "Detailed Description, Reproduction Steps, Impact Analysis, and Fix. "
        "Include the CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/...)."
    ),
    "markdown": (
        "Format as clean generic markdown: # Title, ## Summary, ## Steps to Reproduce, "
        "## Impact, ## Remediation. No platform-specific tags."
    ),
}


def build_report_prompt(data: "ReportData") -> str:
    """Build the user prompt from ReportData for the LLM."""
    platform = (data.platform or "hackerone").lower()
    guidance = PLATFORM_GUIDANCE.get(platform, PLATFORM_GUIDANCE["markdown"])

    sections = [
        f"# Report Generation Request",
        f"",
        f"**Target:** {data.company_name} ({data.base_domain})",
        f"**Platform:** {platform}",
        f"**Date:** {data.generation_date}",
        f"",
        f"## Platform Formatting",
        guidance,
        f"",
        f"## Summary Statistics",
        f"Critical: {data.summary_stats.critical} | High: {data.summary_stats.high} | "
        f"Medium: {data.summary_stats.medium} | Low: {data.summary_stats.low} | "
        f"Info: {data.summary_stats.info}",
        f"",
        f"## Findings",
        f"Generate one complete report per finding below. Separate each report with `---`.",
        f"",
    ]

    for i, fg in enumerate(data.finding_groups, 1):
        sections.append(f"### Finding {i}: {fg.title}")
        sections.append(f"- Severity: {fg.severity} (CVSS: {fg.cvss_score})")
        sections.append(f"- Source tool: {fg.source_tool}")
        if fg.description:
            sections.append(f"- Description: {fg.description}")
        if fg.remediation:
            sections.append(f"- Remediation hint: {fg.remediation}")
        sections.append(f"- Affected assets:")
        for asset in fg.affected_assets:
            sections.append(f"  - {asset.asset_value} (port {asset.port}/{asset.protocol})")
            if asset.poc:
                sections.append(f"  - PoC: ```\n{asset.poc}\n```")
        sections.append("")

    return "\n".join(sections)


__all__ = ["SYSTEM_PROMPT", "build_report_prompt", "PLATFORM_GUIDANCE"]
```

### LLM Renderer

```python
# workers/reporting_worker/renderers/llm_renderer.py
"""LLM-powered report renderer for persuasive, platform-ready reports."""
from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

from lib_webbh.llm_client import LLMClient
from lib_webbh.prompts.report_writer import SYSTEM_PROMPT, build_report_prompt

if TYPE_CHECKING:
    from workers.reporting_worker.deduplicator import ReportData


class LLMRenderer:
    """Generates reports by sending finding data to the local LLM."""

    def __init__(self, model: str | None = None):
        self._model = model

    async def render(self, data: ReportData, output_dir: str) -> list[str]:
        client = LLMClient(model=self._model)
        prompt = build_report_prompt(data)

        response = await client.generate(
            prompt=prompt,
            system=SYSTEM_PROMPT,
            max_tokens=8192,
            temperature=0.3,
        )

        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", data.company_name)[:50]
        filename = f"{safe_name}_{data.generation_date}_{data.platform}_llm.md"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w") as f:
            f.write(response.text)

        return [filepath]
```

### Step-by-step implementation

1. Write failing test for `build_report_prompt` (check that company name, finding, CVSS, PoC, and platform name appear in output for all 5 platforms)
2. Run test — verify fail
3. Implement `shared/lib_webbh/prompts/report_writer.py`
4. Run test — verify pass
5. Write failing test for `LLMRenderer.render()` (mock `LLMClient`, check file written)
6. Run test — verify fail
7. Implement `workers/reporting_worker/renderers/llm_renderer.py`
8. Run test — verify pass
9. Wire into pipeline: add to `FORMAT_RENDERERS` dict:
   ```python
   "llm_hackerone": LLMRenderer,
   "llm_bugcrowd": LLMRenderer,
   "llm_intigriti": LLMRenderer,
   "llm_yeswehack": LLMRenderer,
   "llm_markdown": LLMRenderer,
   ```
10. If pipeline currently calls renderers synchronously, update to `await` async renderers (or detect via `inspect.iscoroutinefunction`).
11. Update `orchestrator/main.py` `ReportCreate.formats` Literal to include all 5 new format keys.
12. Write integration test verifying all 5 keys are in `FORMAT_RENDERERS`.
13. Run all tests.
14. Commit: `feat(reporting): add LLM-powered report writer for 5 bug bounty platforms`

---

## Task 2: Vulnerability Reasoning Engine (#1) — 10 Analysis Types

New worker that analyzes all findings for a target using the local LLM to produce actionable intelligence across **10 analysis dimensions**.

**Files:**
- Create: `shared/lib_webbh/prompts/reasoning.py`
- Create: `workers/reasoning_worker/__init__.py`
- Create: `workers/reasoning_worker/main.py`
- Create: `workers/reasoning_worker/analyzer.py`
- Create: `docker/Dockerfile.reasoning`
- Modify: `shared/lib_webbh/database.py` (add `VulnerabilityInsight` model)
- Modify: `shared/lib_webbh/__init__.py` (export new model)
- Modify: `orchestrator/main.py` (add insight endpoints + trigger endpoint)
- Modify: `orchestrator/dependency_map.py` (add reasoning after chain_worker)
- Test: `tests/test_reasoning_worker.py`

### The 10 Analysis Types

| # | Field | What it answers |
|---|-------|-----------------|
| 1 | `severity_assessment` | Is the tool's severity rating correct? (string: critical/high/medium/low/info) |
| 2 | `exploitability` | How realistic is exploitation in the wild? (text) |
| 3 | `false_positive_likelihood` | Confidence that this is a false positive (float 0.0–1.0) |
| 4 | `chain_hypotheses` | Can this vuln combine with others for bigger impact? (JSON array) |
| 5 | `next_steps` | What manual testing should come next? (text) |
| 6 | `bounty_estimate` | Likely payout range for this finding on this platform (JSON: `{low, high, currency}`) |
| 7 | `duplicate_likelihood` | Probability this is already reported (float 0.0–1.0) |
| 8 | `owasp_cwe` | OWASP 2021 category + CWE ID (JSON: `{owasp, cwe_id, cwe_name}`) |
| 9 | `report_readiness` | Is the finding ready to submit? (float 0.0–1.0 + text notes) |
| 10 | `asset_criticality` | Is the affected asset a critical path? (string: critical/high/medium/low + text) |

### Extended DB Model: VulnerabilityInsight

```python
class VulnerabilityInsight(TimestampMixin, Base):
    """LLM-generated multi-dimensional analysis of a vulnerability."""

    __tablename__ = "vulnerability_insights"
    __table_args__ = (
        Index("ix_insights_target", "target_id"),
        Index("ix_insights_vuln", "vulnerability_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    vulnerability_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerabilities.id"))

    # 1. Severity re-assessment
    severity_assessment: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    # 2. Exploitability analysis
    exploitability: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # 3. False positive detection
    false_positive_likelihood: Mapped[float] = mapped_column(Float, default=0.0)
    # 4. Chain hypotheses
    chain_hypotheses: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # 5. Next-step recommendations
    next_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # 6. Bounty estimate
    bounty_estimate: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # 7. Duplicate likelihood
    duplicate_likelihood: Mapped[float] = mapped_column(Float, default=0.0)
    # 8. OWASP/CWE mapping
    owasp_cwe: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # 9. Report-readiness score
    report_readiness_score: Mapped[float] = mapped_column(Float, default=0.0)
    report_readiness_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # 10. Asset criticality inference
    asset_criticality: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    asset_criticality_rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Overall metadata
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    raw_analysis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship("Target")
    vulnerability: Mapped["Vulnerability"] = relationship("Vulnerability")
```

### Analyzer Architecture

The analyzer works in batches to manage context window limits:
1. Query all vulns + affected assets + observations + tech stack for target
2. Group vulns by severity (critical first)
3. For each batch (max 10 vulns per call):
   - Build prompt with vuln details, asset context, tech stack info, platform name
   - Call `LLMClient.generate(..., json_mode=True)` — Ollama's native JSON mode guarantees parseable output
   - Parse response into `VulnerabilityInsight` records (one per vuln in batch)
4. Store all insights in DB
5. Publish SSE event: `REASONING_COMPLETE` on `events:{target_id}` stream

### Prompt Strategy

System prompt uses `REASONING_SYSTEM` from `pentestgpt_adapted.py`.

User prompt provides per batch:
- Target info (domain, tech stack fingerprint, bounty platform name)
- Batch of vulns with: title, severity, CVSS, description, PoC, source tool, affected asset, observations
- **Required JSON schema** — analyzer instructs the LLM to emit an object with a `"insights"` array, each entry having all 10 fields for one vuln by ID

Example schema instruction in the user prompt:

```
Respond with valid JSON matching this schema:
{
  "insights": [
    {
      "vulnerability_id": <int>,
      "severity_assessment": "critical|high|medium|low|info",
      "exploitability": "<text>",
      "false_positive_likelihood": <float 0.0-1.0>,
      "chain_hypotheses": [{"with_vuln_id": <int>, "description": "<text>"}],
      "next_steps": "<text>",
      "bounty_estimate": {"low": <int>, "high": <int>, "currency": "USD"},
      "duplicate_likelihood": <float 0.0-1.0>,
      "owasp_cwe": {"owasp": "A01:2021", "cwe_id": 79, "cwe_name": "XSS"},
      "report_readiness_score": <float 0.0-1.0>,
      "report_readiness_notes": "<text>",
      "asset_criticality": "critical|high|medium|low",
      "asset_criticality_rationale": "<text>",
      "confidence": <float 0.0-1.0>
    }
  ]
}
```

### Step-by-step implementation

1. Write failing test for prompt builder (`build_reasoning_prompt`)
2. Run test — verify fail
3. Implement `shared/lib_webbh/prompts/reasoning.py` with:
   - `REASONING_SYSTEM` re-export from `pentestgpt_adapted`
   - `build_reasoning_prompt(target_info, vulns_batch)` returning prompt string
   - `REQUIRED_SCHEMA_INSTRUCTION` constant
4. Run test — verify pass
5. Write failing test for analyzer (`analyze_findings`) — mock LLM, check DB writes
6. Run test — verify fail
7. Add `VulnerabilityInsight` model to `database.py` (all 10 analysis fields + metadata)
8. Implement `workers/reasoning_worker/analyzer.py`:
   - `query_target_context(session, target_id)` — loads vulns + assets + tech fingerprint
   - `chunk_vulns(vulns, batch_size=10)` — batch generator
   - `parse_llm_response(response_text) -> list[dict]` — json.loads + schema validation
   - `persist_insights(session, target_id, insights)` — bulk insert
   - `analyze_findings(target_id, session)` — orchestrates above, publishes SSE
9. Run test — verify pass
10. Write failing test for worker main loop (mock Redis queue, mock analyzer)
11. Run test — verify fail
12. Implement `workers/reasoning_worker/main.py` following existing worker pattern (`listen_priority_queues`, heartbeat, `handle_message`)
13. Create `docker/Dockerfile.reasoning` (inherits from `Dockerfile.base`)
14. Add `reasoning-worker` service to `docker-compose.yml`
15. Run test — verify pass
16. Add orchestrator endpoints:
    - `POST /api/v1/targets/{id}/analyze` — push task to `reasoning_queue`
    - `GET /api/v1/targets/{id}/insights` — list `VulnerabilityInsight` records
    - `GET /api/v1/vulnerabilities/{id}/insight` — single insight for a vuln
17. Add `reasoning` to `orchestrator/dependency_map.py` after `chain_worker`:
    ```python
    "reasoning":  ["chain_worker"],
    "reporting":  ["reasoning"],  # reporting now waits for reasoning
    ```
18. Run all tests
19. Commit: `feat(reasoning): add LLM-powered vulnerability reasoning engine with 10 analysis types`

---

## Task 3: Bug Bounty Platform API Integration (#11) — 4 Platforms

Direct API integration with **HackerOne, Bugcrowd, Intigriti, and YesWeHack** for scope import, report submission, and status sync.

**Files:**
- Create: `shared/lib_webbh/platform_api/__init__.py`
- Create: `shared/lib_webbh/platform_api/base.py`
- Create: `shared/lib_webbh/platform_api/hackerone.py`
- Create: `shared/lib_webbh/platform_api/bugcrowd.py`
- Create: `shared/lib_webbh/platform_api/intigriti.py`
- Create: `shared/lib_webbh/platform_api/yeswehack.py`
- Modify: `shared/lib_webbh/database.py` (extend BountySubmission with `external_id`, `platform_response`)
- Modify: `shared/lib_webbh/__init__.py` (export platform API clients)
- Modify: `orchestrator/main.py` (add platform endpoints)
- Test: `tests/test_platform_api.py`

### Abstract Base Class

```python
# shared/lib_webbh/platform_api/base.py
"""Abstract base for all bug bounty platform API clients."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ScopeEntry:
    """Normalized scope entry from any platform."""
    asset_type: str      # domain, ip, wildcard, cidr, mobile_app, etc.
    asset_value: str
    eligible_for_bounty: bool
    max_severity: str | None = None


@dataclass
class SubmissionResult:
    """Result of submitting a report to a platform."""
    external_id: str
    status: str
    platform_url: str | None = None
    raw_response: dict | None = None


class PlatformClient(ABC):
    """Abstract base for platform API clients."""

    @abstractmethod
    async def import_scope(self, program_handle: str) -> list[ScopeEntry]:
        """Fetch the program's scope from the platform."""
        ...

    @abstractmethod
    async def submit_report(
        self,
        program_handle: str,
        title: str,
        body: str,
        severity: str,
        **kwargs,
    ) -> SubmissionResult:
        """Submit a vulnerability report and return the external ID."""
        ...

    @abstractmethod
    async def sync_status(self, external_id: str) -> str:
        """Return the current status of a submitted report."""
        ...
```

### Platform API References

| Platform | Base URL | Auth | Scope endpoint | Submit endpoint | Status endpoint |
|----------|----------|------|----------------|-----------------|-----------------|
| HackerOne | `https://api.hackerone.com/v1` | `X-Auth-Token` header + basic auth username | `GET /programs/{handle}` | `POST /reports` | `GET /reports/{id}` |
| Bugcrowd | `https://api.bugcrowd.com` | `Authorization: Token {token}` | `GET /bounties/{code}` | `POST /submissions` | `GET /submissions/{id}` |
| Intigriti | `https://api.intigriti.com/external/researcher/v1` | `Authorization: Bearer {token}` | `GET /programs/{handle}` | `POST /submissions` | `GET /submissions/{id}` |
| YesWeHack | `https://apps.yeswehack.com/api` | `Authorization: Bearer {token}` | `GET /programs/{slug}` | `POST /programs/{slug}/reports` | `GET /reports/{id}` |

> **API doc note:** Each platform's public API has changed over time. Implementers should verify exact paths against current docs (HackerOne, Bugcrowd, Intigriti, YesWeHack developer portals) before coding — the paths above reflect the structure as documented in each platform's public API reference.

### New Endpoints

```
POST /api/v1/platforms/{platform}/import-scope   — Import scope from a program
                                                     platform in {hackerone, bugcrowd, intigriti, yeswehack}
POST /api/v1/bounties/{id}/submit                — Submit report to platform API
GET  /api/v1/bounties/{id}/sync                  — Sync status from platform
POST /api/v1/platforms/configure                 — Store platform API credentials (env-backed)
```

### Environment Variables

```
HACKERONE_API_TOKEN=
HACKERONE_API_USERNAME=
BUGCROWD_API_TOKEN=
INTIGRITI_API_TOKEN=
YESWEHACK_API_TOKEN=
```

### Step-by-step implementation

1. Write failing test for `PlatformClient` base interface
2. Run test — verify fail
3. Implement `base.py` with `ScopeEntry`, `SubmissionResult`, and abstract `PlatformClient`
4. Run test — verify pass
5. For each of HackerOne, Bugcrowd, Intigriti, YesWeHack:
   a. Write failing test (mock `httpx.AsyncClient` via `respx` or `MagicMock`)
   b. Run test — verify fail
   c. Implement the platform client
   d. Run test — verify pass
6. Add `external_id` and `platform_response` columns to `BountySubmission` model
7. Add orchestrator endpoints (dispatch to the right client based on platform name)
8. Add `PLATFORM_CLIENTS` registry in `platform_api/__init__.py` for dynamic dispatch:
   ```python
   PLATFORM_CLIENTS = {
       "hackerone": HackerOneClient,
       "bugcrowd": BugcrowdClient,
       "intigriti": IntigritiClient,
       "yeswehack": YesWeHackClient,
   }
   ```
9. Run all tests
10. Commit: `feat(platforms): add HackerOne, Bugcrowd, Intigriti, and YesWeHack API integration`

---

## Task 4: Adaptive Scan Intelligence (#4)

Learning system that tracks tool hit rates per tech stack and auto-generates optimal playbooks. **Unchanged from the original plan.**

**Files:**
- Create: `shared/lib_webbh/scan_intelligence.py`
- Create: `tests/test_scan_intelligence.py`
- Modify: `shared/lib_webbh/database.py` (add `ToolHitRate` model)
- Modify: `shared/lib_webbh/__init__.py` (export new symbols)
- Modify: `shared/lib_webbh/playbooks.py` (add `generate_adaptive_playbook()`)
- Modify: `orchestrator/event_engine.py` (use adaptive playbook when available)
- Modify: `orchestrator/main.py` (add intelligence endpoints)
- Test: `tests/test_adaptive_playbook.py`

### New DB Model: ToolHitRate

```python
class ToolHitRate(TimestampMixin, Base):
    """Tracks finding success rates per tool per tech stack fingerprint."""

    __tablename__ = "tool_hit_rates"
    __table_args__ = (
        UniqueConstraint("tech_fingerprint", "tool_name", name="uq_hit_rate_tech_tool"),
        Index("ix_hit_rate_fingerprint", "tech_fingerprint"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tech_fingerprint: Mapped[str] = mapped_column(String(255))
    tool_name: Mapped[str] = mapped_column(String(100))
    total_runs: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    confirmed_findings: Mapped[int] = mapped_column(Integer, default=0)
    avg_runtime_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    last_hit_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
```

### Adaptive Playbook Rules

- Skip tools with <1% hit rate for this fingerprint
- Boost concurrency for tools with >20% hit rate
- Keep all tools if <10 total runs (insufficient data — cold start protection)

### Feedback Loop

When a bounty is paid (`PATCH /api/v1/bounties/{id}` with `actual_payout > 0`):
1. Look up the vulnerability's `source_tool`
2. Look up the target's tech fingerprint
3. Increment `confirmed_findings` for that (fingerprint, tool) pair
4. Future playbook generation automatically improves

### Step-by-step implementation

1. Write failing test for tech stack fingerprinting function
2. Run test — verify fail
3. Implement `scan_intelligence.py`:
   - `fingerprint_tech_stack(observations: list[dict]) -> str`
   - `record_tool_result(tech_fp, tool_name, finding_count, confirmed, runtime_s)`
   - `get_tool_rankings(tech_fp) -> list[ToolRanking]`
   - `generate_adaptive_playbook(tech_fp, base_playbook) -> PlaybookConfig`
4. Run test — verify pass
5. Write failing test for adaptive playbook generation
6. Run test — verify fail
7. Implement `generate_adaptive_playbook()` with the three rules above
8. Run test — verify pass
9. Add `ToolHitRate` model to `database.py`
10. Integrate recording into worker pipelines: after each tool completes, call `record_tool_result`
11. Add orchestrator endpoints:
    - `GET /api/v1/intelligence/rankings?tech_fingerprint=...`
    - `GET /api/v1/intelligence/playbook?target_id=...`
    - `POST /api/v1/intelligence/feedback`
12. Run all tests
13. Commit: `feat(intelligence): add adaptive scan intelligence with tool hit rate tracking`

---

## Task 5: Autonomous Exploit Chain Discovery (#5) — 6 Quality Constraints

Extends the chain worker with LLM-based chain hypothesis generation that discovers novel vulnerability chains beyond the 8 hardcoded templates. **All LLM-proposed chains must satisfy 6 quality constraints.**

**Files:**
- Create: `shared/lib_webbh/prompts/chain_discovery.py`
- Create: `workers/chain_worker/tools/ai_chain_discoverer.py`
- Create: `tests/test_ai_chain_discovery.py`
- Modify: `workers/chain_worker/pipeline.py` (add AI discovery stage between evaluation and execution)
- Modify: `workers/chain_worker/tools/__init__.py` (register new tool)

### Pipeline Position

```
data_collection → chain_evaluation → ai_chain_discovery → chain_execution → reporting
```

### The 6 Quality Constraints

Every LLM-proposed chain must pass **all six** to be appended to the viable buckets:

| # | Constraint | Enforcement |
|---|-----------|-------------|
| 1 | **Minimum finding confidence** | All vulns in the chain must have `evidence_confidence >= 0.7` (computed from source tool quality + PoC presence). Chains referencing any weaker finding are rejected. |
| 2 | **Severity gate** | At least one vuln in the chain must be Medium-or-higher severity. Info-only chains are rejected. |
| 3 | **Chain length limit** | 2–4 steps inclusive. Shorter (1 step) is not a chain; longer (5+) is usually LLM hallucination. |
| 4 | **Per-chain confidence score** | LLM must rate each chain 0.0–1.0 on how likely it is to actually work. ChainExecutor runs highest-confidence first. Chains below a `MIN_CHAIN_CONFIDENCE` threshold (default 0.5) are dropped. |
| 5 | **Distinctness check** | Reject chains where ≥80% of steps overlap with any existing template chain result (set overlap via `jaccard_similarity(chain_a.vuln_ids, chain_b.vuln_ids)`). |
| 6 | **Stated goal** | Each chain must include a non-empty `goal` string articulating what the attacker gains (e.g., "full account takeover", "tenant data exfiltration", "RCE on application server"). |

### AI Chain Discoverer Flow

1. Receives all findings from `kwargs["_findings"]` (set by `FindingsCollector`)
2. Receives existing template chain results from `kwargs["_buckets"]` (set by `ChainEvaluator`)
3. Pre-filters findings to those with `evidence_confidence >= 0.7` (Constraint 1)
4. Builds prompt with filtered findings + existing chain results + required JSON schema
5. Calls `LLMClient.generate(..., json_mode=True)` using `CHAIN_DISCOVERY_SYSTEM` from `pentestgpt_adapted.py`
6. Parses response — expects JSON with `"chains"` array, each chain having:
   - `vuln_ids: list[int]`
   - `steps: list[str]`
   - `goal: str`
   - `confidence: float`
   - `expected_impact: str`
7. Applies **all 6 constraints** as a filter pipeline
8. Appends surviving chains (up to `MAX_AI_CHAINS`, default 5) to `kwargs["_buckets"]["viable"]` sorted by confidence descending

### Environment Variables

```
MAX_AI_CHAINS=5
MIN_CHAIN_CONFIDENCE=0.5
MIN_FINDING_CONFIDENCE=0.7
MAX_CHAIN_OVERLAP=0.8
```

### Step-by-step implementation

1. Write failing test for `build_chain_prompt` (check findings, template chains, JSON schema instruction, goal requirement are all present)
2. Run test — verify fail
3. Implement `shared/lib_webbh/prompts/chain_discovery.py`:
   - `CHAIN_DISCOVERY_SYSTEM` re-export from `pentestgpt_adapted`
   - `build_chain_prompt(findings, existing_chains)` with strict JSON schema instructions
4. Run test — verify pass
5. Write failing tests for each of the 6 constraint filters (one test per constraint + one integration test)
6. Run tests — verify fail
7. Implement `workers/chain_worker/tools/ai_chain_discoverer.py`:
   - `class AIChainDiscoverer(ChainTool)` — follows existing chain tool pattern
   - `filter_by_confidence(chains)` — Constraint 1
   - `filter_by_severity(chains, findings)` — Constraint 2
   - `filter_by_length(chains)` — Constraint 3
   - `filter_by_chain_confidence(chains)` — Constraint 4
   - `filter_by_distinctness(chains, template_chains)` — Constraint 5 (Jaccard ≥0.8 → drop)
   - `filter_by_goal(chains)` — Constraint 6
   - `discover(findings, buckets, kwargs)` — orchestrates LLM call + filters + append
8. Run tests — verify pass
9. Add `ai_chain_discovery` stage to chain pipeline between evaluation and execution
10. Register tool in `workers/chain_worker/tools/__init__.py`
11. Run all chain worker tests
12. Commit: `feat(chains): add LLM-powered exploit chain discovery with 6 quality constraints`

---

## Task 6: Payload Mutation Engine (#9) — Pure Python, Multi-Vuln, No WASM

**Major revision.** The original plan used Wasmtime + QuickJS to execute payloads. That was dropped because QuickJS has no DOM and can't validate real XSS, and the WASM layer added significant complexity for limited value. Real payload validation happens during live scanning via the existing proxy/client-side workers.

This task becomes a **pure-Python mutation engine** that generates WAF-bypass variants across many vulnerability types, learns which mutations work, and integrates with existing workers.

**Files:**
- Create: `workers/sandbox_worker/__init__.py`
- Create: `workers/sandbox_worker/main.py`
- Create: `workers/sandbox_worker/mutator.py`
- Create: `workers/sandbox_worker/context.py` (context-aware mutation dispatch)
- Create: `workers/sandbox_worker/chaining.py` (multi-mutation chaining)
- Create: `workers/sandbox_worker/waf_fingerprint.py` (auto WAF detection)
- Create: `workers/sandbox_worker/payload_corpus.py` (seed payloads per vuln type)
- Create: `docker/Dockerfile.sandbox`
- Modify: `docker-compose.yml` (add sandbox-worker service — no GPU, no WASM runtime needed)
- Modify: `shared/lib_webbh/database.py` (add `MutationOutcome` model for success feedback)
- Modify: `orchestrator/dependency_map.py` (sandbox_worker as utility service)
- Modify: `orchestrator/main.py` (add sandbox endpoints)
- Test: `tests/test_sandbox_worker.py`

### Architecture

The sandbox worker is now a **mutation service**:
1. Listens on `sandbox_queue` for mutation/bypass requests from `client_side` and `input_validation` workers
2. Accepts `(payload, vuln_type, context, waf_profile_or_none)` and returns a ranked list of mutated variants
3. Records which mutations actually bypass WAFs (via feedback from the requesting worker) to learn over time
4. Exposes HTTP endpoints on the orchestrator for manual queries

### Vulnerability Types Supported

| Vuln type | Mutation strategies |
|-----------|---------------------|
| `xss` | url_encode, double_url_encode, html_entity, unicode_escape, case_variation, null_byte_inject, comment_insert, tag_nesting, event_handler_swap, svg_wrapper, math_wrapper |
| `sqli` | comment_insert (`/**/`, `--`, `#`), case_variation, char_concat (`CHAR(0x41)`), hex_encoding, whitespace_substitution (`%0a`, `%09`), quote_doubling, union_alternative_syntax |
| `ssrf` | url_parser_confusion (`@`, `#`, `?`), ip_encoding (decimal, octal, hex, IPv6), redirect_chain, dns_rebinding_hints, localhost_variants |
| `command_injection` | shell_metacharacter_variation (`;`, `\|`, `&&`, backticks, `$()`), whitespace_substitution (`${IFS}`, `\t`), quote_wrapping, encoding (base64 piped to shell) |
| `xxe` | external_entity_variants, parameter_entity, svg_xxe_wrapper, utf16_encoding |
| `template_injection` | engine_specific_syntax (Jinja2 `{{}}`, Twig `{{}}`, ERB `<%= %>`, Freemarker `${}`, Velocity `#set`), whitespace_variation, filter_bypass |
| `path_traversal` | dot_encoding (`%2e`, `%2e%2e`), slash_variation (`/`, `\\`, `%2f`), double_encoding, null_byte_append |

### Context-Aware Mutation

```python
# workers/sandbox_worker/context.py
from enum import Enum

class InjectionContext(Enum):
    HTML_TAG = "html_tag"                 # Inside an HTML tag body
    HTML_ATTR = "html_attr"               # Inside an HTML attribute value
    HTML_ATTR_EVENT = "html_attr_event"   # Inside an event handler attribute
    JS_STRING = "js_string"               # Inside a JavaScript string literal
    JS_CODE = "js_code"                   # Inside raw JavaScript code
    URL_PARAM = "url_param"               # Inside a URL query parameter
    URL_PATH = "url_path"                 # Inside a URL path segment
    SQL_STRING = "sql_string"             # Inside a SQL string literal
    SQL_NUMBER = "sql_number"             # Inside a SQL numeric literal
    HEADER_VALUE = "header_value"         # Inside an HTTP header value
    JSON_STRING = "json_string"           # Inside a JSON string value
```

The mutator accepts an `InjectionContext` and only applies mutations appropriate to that context. For example, `html_entity` encoding is valid in `HTML_TAG` but breaks `JS_STRING`.

### Chained Mutations

Most modern WAFs block single-transformation bypasses. `workers/sandbox_worker/chaining.py` applies 2–3 mutations in sequence (configurable `MAX_MUTATION_CHAIN_DEPTH=3`). It prunes combinatorial explosion by:
- Prioritizing chains with high historical success (from `MutationOutcome` table)
- Capping total variants per request (`MAX_VARIANTS_PER_REQUEST=50`)

### WAF Fingerprinting

`waf_fingerprint.py` detects WAF type from an HTTP response (headers, body, status codes):

```python
WAF_SIGNATURES = {
    "cloudflare": {
        "headers": {"server": ["cloudflare"], "cf-ray": None},
        "body_patterns": [r"Attention Required.*Cloudflare"],
        "status_codes": [403, 503],
    },
    "akamai": {
        "headers": {"server": ["AkamaiGHost"]},
        "body_patterns": [r"Reference #\d+\.\w+"],
    },
    "aws_waf": {
        "headers": {"x-amzn-requestid": None},
        "body_patterns": [r"<AccessDenied>"],
    },
    "modsecurity": {
        "body_patterns": [r"Mod_?Security", r"Not Acceptable!"],
        "status_codes": [406, 501],
    },
    "imperva": {
        "headers": {"x-iinfo": None, "x-cdn": ["Incapsula"]},
    },
    "f5_bigip": {
        "cookies": ["TS01", "BIGipServer"],
    },
    "sucuri": {
        "headers": {"server": ["Sucuri/Cloudproxy"], "x-sucuri-id": None},
    },
}
```

`fingerprint_waf(response_headers, response_body, status_code) -> str | None` returns the detected WAF name or `None`.

### Success Feedback Loop

New DB model:

```python
class MutationOutcome(TimestampMixin, Base):
    """Records whether a mutation successfully bypassed a WAF in real scanning."""

    __tablename__ = "mutation_outcomes"
    __table_args__ = (
        Index("ix_mutation_outcomes_waf", "waf_profile"),
        Index("ix_mutation_outcomes_vuln_type", "vuln_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_type: Mapped[str] = mapped_column(String(50))
    waf_profile: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    mutation_chain: Mapped[str] = mapped_column(String(500))  # e.g., "url_encode|case_variation"
    context: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    bypassed: Mapped[bool] = mapped_column(Boolean, default=False)
    total_attempts: Mapped[int] = mapped_column(Integer, default=1)
    successful_attempts: Mapped[int] = mapped_column(Integer, default=0)
```

When a worker uses a mutated payload and gets a successful finding (or gets blocked), it calls:

```python
POST /api/v1/sandbox/feedback
{
  "vuln_type": "xss",
  "waf_profile": "cloudflare",
  "mutation_chain": "url_encode|case_variation",
  "context": "html_attr",
  "bypassed": true
}
```

The mutator ranks future mutation chains by `successful_attempts / total_attempts` for the matching `(vuln_type, waf_profile, context)`.

### Payload Corpus

`payload_corpus.py` holds seed payloads per `(vuln_type, context)` — e.g.:

```python
CORPUS = {
    ("xss", InjectionContext.HTML_TAG): [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    ("sqli", InjectionContext.SQL_STRING): [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--",
    ],
    # ... all supported (vuln_type, context) combos
}
```

Workers requesting mutations without a base payload get the corpus seeds as starting points.

### Worker Integration

`client_side` and `input_validation` workers push to `sandbox_queue` when:
- A payload gets blocked (status 403/406, WAF signature in response, etc.)
- They need variants for fuzzing

Request message format:

```json
{
  "type": "mutate",
  "vuln_type": "xss",
  "base_payload": "<script>alert(1)</script>",
  "context": "html_attr",
  "waf_profile": "cloudflare",
  "reply_queue": "client_side_queue",
  "reply_correlation_id": "..."
}
```

Response is pushed back to `reply_queue` with the ranked mutations.

### New Endpoints

```
POST /api/v1/sandbox/mutate          — Generate payload variants for a given vuln type + context
POST /api/v1/sandbox/bypass          — Generate WAF-specific bypass variants (auto-detects WAF if response provided)
POST /api/v1/sandbox/fingerprint     — Fingerprint WAF from HTTP response
POST /api/v1/sandbox/feedback        — Record mutation outcome
GET  /api/v1/sandbox/waf-profiles    — List known WAF profiles
GET  /api/v1/sandbox/corpus          — List seed payloads per (vuln_type, context)
```

### Environment Variables

```
MAX_MUTATION_CHAIN_DEPTH=3
MAX_VARIANTS_PER_REQUEST=50
MIN_HISTORICAL_CONFIDENCE=0.1   # Drop mutations with <10% historical success
```

### Step-by-step implementation

1. Write failing test for base mutator (per-strategy unit tests — url_encode, html_entity, case_variation, etc.)
2. Run tests — verify fail
3. Implement `workers/sandbox_worker/mutator.py` with all mutation strategies for XSS first (11 strategies from the original plan)
4. Run tests — verify pass
5. Write failing tests for SQLi, SSRF, command injection, XXE, template injection, path traversal mutations (one test file per vuln type or one big parameterized test)
6. Run tests — verify fail
7. Extend mutator with all 7 vuln types
8. Run tests — verify pass
9. Write failing test for `InjectionContext` dispatch — given a context, only returns context-valid mutations
10. Run test — verify fail
11. Implement `workers/sandbox_worker/context.py` and wire into mutator
12. Run test — verify pass
13. Write failing test for chaining — 2 mutations applied in sequence produces correct compound result
14. Run test — verify fail
15. Implement `workers/sandbox_worker/chaining.py` with depth cap + variant cap
16. Run test — verify pass
17. Write failing test for WAF fingerprinting (mock responses for each WAF signature)
18. Run test — verify fail
19. Implement `workers/sandbox_worker/waf_fingerprint.py` with all 7 WAF signatures
20. Run test — verify pass
21. Write failing test for `MutationOutcome` DB writes + ranking query
22. Run test — verify fail
23. Add `MutationOutcome` model to `database.py`, implement ranking logic in mutator
24. Run test — verify pass
25. Implement `workers/sandbox_worker/payload_corpus.py` with seed payloads for all supported `(vuln_type, context)` combos
26. Write test that verifies corpus has entries for every supported vuln type
27. Run test — verify pass
28. Implement `workers/sandbox_worker/main.py` following worker pattern (listen on `sandbox_queue`, reply-queue routing)
29. Create `docker/Dockerfile.sandbox` (lightweight — no WASM runtime, no headless browser)
30. Add `sandbox-worker` to `docker-compose.yml` (no GPU, minimal memory)
31. Add orchestrator endpoints (`/mutate`, `/bypass`, `/fingerprint`, `/feedback`, `/waf-profiles`, `/corpus`)
32. Wire `client_side` and `input_validation` workers to push to `sandbox_queue` when blocked (follow-up task — can be done incrementally after the sandbox worker lands)
33. Run all tests
34. Commit: `feat(sandbox): add pure-Python payload mutation engine with WAF fingerprinting and feedback loop`

---

## Environment Variables (All Features)

Add to `shared/.env` template:

```bash
# LLM (Tasks 0, 1, 2, 5) — local Ollama
LLM_BASE_URL=http://ollama:11434
LLM_MODEL=qwen3:14b
LLM_MAX_TOKENS=4096
LLM_TIMEOUT=600.0

# Chain discovery (Task 5)
MAX_AI_CHAINS=5
MIN_CHAIN_CONFIDENCE=0.5
MIN_FINDING_CONFIDENCE=0.7
MAX_CHAIN_OVERLAP=0.8

# Platform APIs (Task 3)
HACKERONE_API_TOKEN=
HACKERONE_API_USERNAME=
BUGCROWD_API_TOKEN=
INTIGRITI_API_TOKEN=
YESWEHACK_API_TOKEN=

# Sandbox mutation engine (Task 6)
MAX_MUTATION_CHAIN_DEPTH=3
MAX_VARIANTS_PER_REQUEST=50
MIN_HISTORICAL_CONFIDENCE=0.1
```

---

## Docker Services (New)

Add to `docker-compose.yml`:

```yaml
ollama:
  image: ollama/ollama:latest
  container_name: webappbh-ollama
  ports:
    - "11434:11434"
  volumes:
    - ollama-models:/root/.ollama
  environment:
    - OLLAMA_KEEP_ALIVE=24h
    - OLLAMA_NUM_PARALLEL=4
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: all
            capabilities: [gpu]
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
    interval: 30s
    timeout: 10s
    retries: 3

reasoning-worker:
  build:
    context: .
    dockerfile: docker/Dockerfile.reasoning
  depends_on: [postgres, redis, ollama]
  environment: *common-env
  volumes: [shared-config:/app/shared/config]

sandbox-worker:
  build:
    context: .
    dockerfile: docker/Dockerfile.sandbox
  depends_on: [postgres, redis]
  environment: *common-env
  volumes: [shared-config:/app/shared/config]

volumes:
  ollama-models:
```

> **First-run reminder:** After `docker compose up ollama`, pull the model:
> ```bash
> docker compose exec ollama ollama pull qwen3:14b
> ```

---

## Dependency Map Update

```python
DEPENDENCY_MAP = {
    # ... existing entries ...
    "chain_worker":     ["input_validation", "error_handling", "cryptography", "business_logic", "client_side"],
    "reasoning":        ["chain_worker"],    # NEW — runs after chains
    "reporting":        ["reasoning"],       # CHANGED — reporting now waits for reasoning
    # sandbox_worker is a utility service triggered on-demand by other workers, not in DEPENDENCY_MAP
}
```

---

## Testing Strategy

Each feature has:
1. **Unit tests** — mock the LLM client / HTTP clients, test prompt building, parsing, DB operations, mutation strategies
2. **Integration tests** — full pipeline with mocked external services (Ollama, platform APIs)
3. All tests use `anyio_backend = "asyncio"` and aiosqlite for in-memory SQLite

Tests **never** call real Ollama or platform APIs. All external calls are mocked (`httpx` responses via `respx` or `MagicMock` patches).

**Task 0 smoke test exception:** The LLM client's unit tests mock httpx. Before closing Task 0, run a manual smoke test against the real Ollama container to verify the end-to-end path works. This is documented as a step, not committed as an automated test.

---

## Execution Order

Build features in this exact order. Each feature is fully tested and committed before starting the next:

1. **Task 0** — Local LLM Client + Ollama container
2. **Task 1** — Auto-Report Writer (5 formats)
3. **Task 2** — Vulnerability Reasoning Engine (10 analyses)
4. **Task 3** — Bug Bounty Platform API Integration (4 platforms)
5. **Task 4** — Adaptive Scan Intelligence
6. **Task 5** — Autonomous Exploit Chain Discovery (6 constraints)
7. **Task 6** — Payload Mutation Engine (pure Python, no WASM)

---

## Attribution & Licensing Notes

- **PentestGPT prompts** (Task 0 `shared/lib_webbh/prompts/pentestgpt_adapted.py`): Adapted from [PentestGPT](https://github.com/GreyDGL/PentestGPT) under its MIT License. Each adapted prompt has an inline attribution comment. We are not executing PentestGPT code; we only borrow and adapt its system prompts.
- **Ollama / Qwen3**: Ollama is MIT-licensed. Qwen3 model weights are released by Alibaba Cloud under their own license — verify compatibility with the deployment context before production use.
