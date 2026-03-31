# M7: Input Validation Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the input validation worker with 15 stages covering XSS, injection attacks, HTTP parameter pollution, and other input-based vulnerabilities, including SQL injection variants and SSRF testing with callback server integration.

**Architecture:** Single worker with 15+ tools, including Sqlmap variants (generic, Oracle, MSSQL, Postgres). Uses callback server for blind SQL/command injection and SSRF. Traffic proxy for HTTP verb tampering.

**Tech Stack:** Python 3.10, asyncio, lib_webbh, sqlmap, ffuf (shared), Docker.

**Design docs:** `docs/plans/design/2026-03-29-restructure-06-input-validation.md`

---

## Template Variables

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `input_validation` |
| `{WORKER_DIR}` | `workers/input_validation` |
| `{BASE_TOOL_CLASS}` | `InputValidationTool` |
| `{EXPECTED_STAGE_COUNT}` | `15` |

## Stages (WSTG 4.7.1 → 4.7.19, grouped into 15 stages)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | reflected_xss | 4.7.1 | ReflectedXssTester |
| 2 | stored_xss | 4.7.2 | StoredXssTester |
| 3 | http_verb_tampering | 4.7.3 | HttpVerbTamperTester |
| 4 | http_param_pollution | 4.7.4 | HttpParameterPollutionTester |
| 5 | sql_injection | 4.7.5 | SqlmapGenericTool, SqlmapOracleTool, SqlmapMssqlTool, SqlmapPostgresTool |
| 6 | ldap_injection | 4.7.6 | LdapInjectionTester |
| 7 | xml_injection | 4.7.7 | XmlInjectionTester |
| 8 | ssti | 4.7.8 | SstiTester |
| 9 | xpath_injection | 4.7.9 | XpathInjectionTester |
| 10 | imap_smtp_injection | 4.7.10 | ImapSmtpInjectionTester |
| 11 | code_injection | 4.7.11 | CodeInjectionTester |
| 12 | command_injection | 4.7.12 | CommandInjectionTester |
| 13 | format_string | 4.7.13 | FormatStringTester |
| 14 | host_header_injection | 4.7.14 | HostHeaderTester |
| 15 | ssrf | 4.7.15 | SsrfTester |

**Note:** Sections 4.7.16–4.7.19 (LFI, RFI, HTTP Smuggling, WebSocket injection) are included as additional tools within the most relevant stages above. See design doc for details.

## Sqlmap Config Variants

SqlmapOracleTool, SqlmapMssqlTool, SqlmapPostgresTool are NOT separate tools — they are config wrappers around SqlmapGenericTool:

```python
class SqlmapOracleTool(SqlmapGenericTool):
    """Sqlmap configured for Oracle-specific techniques."""
    def build_command(self, target_url, param):
        cmd = super().build_command(target_url, param)
        cmd.extend(["--dbms=Oracle", "--technique=BEUST"])
        return cmd
```

## Docker Binaries

```dockerfile
RUN pip install sqlmap
# Ffuf already installed in config_mgmt image, shared via network
```

## Proxy & Callback Integration

- Stages 5 (sql_injection), 12 (command_injection), 15 (ssrf) use the callback server for blind detection
- Stage 3 (http_verb_tampering) uses the traffic proxy for request manipulation

---

## Task 1: Scaffold Worker Directory Structure

**Files:** Similar to M5, use `new-worker` skill.

**Step 1:** `@new-worker input_validation InputValidationTool 15`

---

## Task 2: Implement Base Tool

**Files:** `workers/input_validation/base_tool.py`

**Step 1:** Add helpers for injection testing, callback integration.

---

## Task 3: Implement Tools Directory

**Files:** 15+ tool files, including Sqlmap variants.

**Step 1:** Implement each tester, focusing on injection payloads and detection.

---

## Task 4: Configure Concurrency

**Files:** `workers/input_validation/concurrency.py`

**Step 1:** Set weights, LIGHT for most, HEAVY for sqlmap stages.

---

## Task 5: Implement Pipeline

**Files:** `workers/input_validation/pipeline.py`

**Step 1:** 15 sequential stages.

---

## Task 6: Update Main Entry Point

**Files:** `workers/input_validation/main.py`

**Step 1:** Listen to appropriate queue.

---

## Task 7: Build Docker Image

**Files:** `workers/input_validation/Dockerfile`

**Step 1:** Install sqlmap.

---

## Task 8: Update Docker Compose

**Files:** `docker-compose.yml`

**Step 1:** Add input_validation service.

---

## Task 9: Add Tests

**Files:** Test files for pipeline and tools.

**Step 1:** Write integration tests.

---

## Task 10: Update Documentation

**Files:** README or docs.

**Step 1:** Document the worker.