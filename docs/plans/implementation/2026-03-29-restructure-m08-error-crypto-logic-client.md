# M8: Error Handling, Cryptography, Business Logic & Client-Side Workers Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build four workers for error handling (2 stages), cryptography auditing (4 stages), business logic testing (9 stages), and client-side analysis (13 stages) with browser automation using Playwright.

**Architecture:** Four separate workers. Client-side worker includes BrowserManager singleton for Playwright. Business logic and error handling integrate with proxy/callback servers.

**Tech Stack:** Python 3.10, asyncio, lib_webbh, testssl.sh, sslyze, playwright, Docker.

**Design docs:** `docs/plans/design/2026-03-29-restructure-07-error-crypto-logic-client.md`

---

## M8a: Error Handling Worker

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `error_handling` |
| `{WORKER_DIR}` | `workers/error_handling` |
| `{BASE_TOOL_CLASS}` | `ErrorHandlingTool` |
| `{EXPECTED_STAGE_COUNT}` | `2` |

### Stages (WSTG 4.8.1 → 4.8.2)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | error_codes | 4.8.1 | ErrorProber |
| 2 | stack_traces | 4.8.2 | StackTraceDetector |

### Base Tool Helpers

```python
    def detect_framework_error_page(self, response_body: str) -> Optional[str]:
        """Match response against known framework error page signatures."""
        ...

    def extract_stack_trace(self, response_body: str) -> list[dict]:
        """Parse stack traces from response bodies."""
        ...
```

---

## M8b: Cryptography Worker

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `cryptography` |
| `{WORKER_DIR}` | `workers/cryptography` |
| `{BASE_TOOL_CLASS}` | `CryptographyTool` |
| `{EXPECTED_STAGE_COUNT}` | `4` |

### Stages (WSTG 4.9.1 → 4.9.4)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | tls_testing | 4.9.1 | TlsAuditor |
| 2 | padding_oracle | 4.9.2 | PaddingOracleTester |
| 3 | plaintext_transmission | 4.9.3 | PlaintextLeakScanner |
| 4 | weak_crypto | 4.9.4 | AlgorithmAuditor |

### Docker Binaries

```dockerfile
RUN apt-get install -y testssl.sh
RUN pip install sslyze
```

---

## M8c: Business Logic Worker

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `business_logic` |
| `{WORKER_DIR}` | `workers/business_logic` |
| `{BASE_TOOL_CLASS}` | `BusinessLogicTool` |
| `{EXPECTED_STAGE_COUNT}` | `9` |

### Stages (WSTG 4.10.1 → 4.10.9)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | data_validation | 4.10.1 | BusinessValidationTester |
| 2 | request_forgery | 4.10.2 | RequestForgeryTester |
| 3 | integrity_checks | 4.10.3 | IntegrityTester |
| 4 | process_timing | 4.10.4 | TimingAnalyzer |
| 5 | rate_limiting | 4.10.5 | RateLimitTester |
| 6 | workflow_bypass | 4.10.6 | WorkflowBypassTester |
| 7 | application_misuse | 4.10.7 | MisuseTester |
| 8 | file_upload_validation | 4.10.8 | FileTypeTester |
| 9 | malicious_file_upload | 4.10.9 | MaliciousUploadTester |

### Proxy & Callback Integration

- Stages 2, 3 use traffic proxy
- Stage 9 uses callback server

---

## M8d: Client-Side Worker

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `client_side` |
| `{WORKER_DIR}` | `workers/client_side` |
| `{BASE_TOOL_CLASS}` | `ClientSideTool` |
| `{EXPECTED_STAGE_COUNT}` | `13` |

### Stages (WSTG 4.11.1 → 4.11.13)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | dom_xss | 4.11.1 | DomSinkAnalyzer (HEAVY) |
| 2 | js_execution | 4.11.2 | JsExecutionTester |
| 3 | html_injection | 4.11.3 | HtmlInjectionTester |
| 4 | open_redirect | 4.11.4 | OpenRedirectTester |
| 5 | css_injection | 4.11.5 | CssInjectionTester |
| 6 | resource_manipulation | 4.11.6 | ResourceManipulationTester |
| 7 | cors_testing | 4.11.7 | CorsTester |
| 8 | flash_crossdomain | 4.11.8 | FlashAuditor |
| 9 | clickjacking | 4.11.9 | ClickjackTester |
| 10 | websocket_testing | 4.11.10 | WebSocketAuditor (HEAVY) |
| 11 | postmessage_testing | 4.11.11 | PostMessageTester (HEAVY) |
| 12 | browser_storage | 4.11.12 | StorageAuditor (HEAVY) |
| 13 | cross_site_script_inclusion | 4.11.13 | XssiTester |

### Additional Task: BrowserManager Singleton

Before implementing tools, create `workers/client_side/browser_manager.py`:

**Test:**
```python
# tests/test_client_side/test_browser_manager.py
import pytest

pytestmark = pytest.mark.anyio


async def test_browser_manager_singleton():
    from workers.client_side.browser_manager import BrowserManager

    browser1 = await BrowserManager.get_browser()
    browser2 = await BrowserManager.get_browser()
    assert browser1 is browser2

    await BrowserManager.cleanup()
```

**Implementation:**
```python
# workers/client_side/browser_manager.py
from playwright.async_api import async_playwright


class BrowserManager:
    _browser = None
    _playwright = None

    @classmethod
    async def get_browser(cls):
        if cls._browser is None:
            cls._playwright = await async_playwright().start()
            cls._browser = await cls._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
        return cls._browser

    @classmethod
    async def new_context(cls):
        browser = await cls.get_browser()
        return await browser.new_context()

    @classmethod
    async def cleanup(cls):
        if cls._browser:
            await cls._browser.close()
            cls._browser = None
        if cls._playwright:
            await cls._playwright.stop()
            cls._playwright = None
```

### Base Tool Helpers

```python
    async def get_browser_context(self):
        """Get a fresh, isolated browser context from the BrowserManager."""
        from .browser_manager import BrowserManager
        return await BrowserManager.new_context()
```

### Docker Binaries

```dockerfile
RUN pip install playwright
RUN playwright install chromium --with-deps
```

---

## Implementation Order

M8a (error_handling) and M8b (cryptography) can be built in parallel. Then M8c (business_logic), then M8d (client_side).

For each worker, follow the worker template tasks T1–T8.