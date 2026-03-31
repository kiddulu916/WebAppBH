# M5: Config Management Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the config management worker with 11 WSTG-aligned stages for network configuration, platform fingerprinting, file handling, backup discovery, API enumeration, HTTP methods testing, HSTS validation, RPC testing, file inclusion detection, subdomain takeover checking, and cloud storage auditing.

**Architecture:** Follows the worker template (`2026-03-29-restructure-worker-template.md`) with base_tool.py → concurrency.py → tools/ → pipeline.py → main.py → Dockerfile. Absorbs tools from fuzzing_worker (Ffuf), recon_core (subdomain takeover), and cloud_worker (cloud storage auditing).

**Tech Stack:** Python 3.10, asyncio, lib_webbh (database, messaging, scope), Docker, subprocess for external tools.

**Design docs:** `docs/plans/design/2026-03-29-restructure-04-config-mgmt.md`

---

## Template Variables

| Variable | Value |
|----------|-------|
| `{WORKER_NAME}` | `config_mgmt` |
| `{WORKER_DIR}` | `workers/config_mgmt` |
| `{BASE_TOOL_CLASS}` | `ConfigMgmtTool` |
| `{EXPECTED_STAGE_COUNT}` | `11` |

## Stages (WSTG 4.2.1 → 4.2.11)

| # | Stage Name | Section ID | Tools |
|---|-----------|-----------|-------|
| 1 | network_config | 4.2.1 | NetworkConfigTester |
| 2 | platform_config | 4.2.2 | PlatformFingerprinter |
| 3 | file_extension_handling | 4.2.3 | FileExtensionTester |
| 4 | backup_files | 4.2.4 | BackupFileFinder, Ffuf |
| 5 | api_discovery | 4.2.5 | ApiDiscoveryTool |
| 6 | http_methods | 4.2.6 | HttpMethodTester |
| 7 | hsts_testing | 4.2.7 | HstsTester |
| 8 | rpc_testing | 4.2.8 | RpcTester |
| 9 | file_inclusion | 4.2.9 | FileInclusionTester |
| 10 | subdomain_takeover | 4.2.10 | SubdomainTakeoverChecker |
| 11 | cloud_storage | 4.2.11 | CloudStorageAuditor |

## All Tools Weight: LIGHT (except Ffuf: HEAVY)

## Base Tool Helpers

Same as InfoGatheringTool (subprocess runner, scope check, save_asset, save_vulnerability).

## Docker Binaries

```dockerfile
RUN go install github.com/ffuf/ffuf/v2@latest
```

## Key Notes

- Stage 4 absorbs Ffuf from fuzzing_worker (file/directory discovery)
- Stage 10 absorbs subdomain takeover detection from recon_core
- Stage 11 absorbs cloud storage auditing from cloud_worker
- All other tools are new implementations

---

## Task 1: Scaffold Worker Directory Structure

**Files:**
- Create: `workers/config_mgmt/`
- Create: `workers/config_mgmt/__init__.py`
- Create: `workers/config_mgmt/base_tool.py`
- Create: `workers/config_mgmt/concurrency.py`
- Create: `workers/config_mgmt/pipeline.py`
- Create: `workers/config_mgmt/main.py`
- Create: `workers/config_mgmt/Dockerfile`
- Create: `workers/config_mgmt/tools/`
- Create: `workers/config_mgmt/tools/__init__.py`

**Step 1: Run the scaffold command**

Use the `new-worker` skill to scaffold the basic structure:

```
@new-worker config_mgmt ConfigMgmtTool 11
```

**Test:** Verify directory structure exists and files are created.

---

## Task 2: Implement Base Tool

**Files:**
- Modify: `workers/config_mgmt/base_tool.py`

**Step 1: Update base_tool.py**

Extend from ReconTool or ApiTestTool as appropriate, add config-specific helpers.

**Test:** Import the base tool successfully.

---

## Task 3: Implement Tools Directory

**Files:**
- Create: `workers/config_mgmt/tools/network_config_tester.py`
- Create: `workers/config_mgmt/tools/platform_fingerprinter.py`
- Create: `workers/config_mgmt/tools/file_extension_tester.py`
- Create: `workers/config_mgmt/tools/backup_file_finder.py`
- Create: `workers/config_mgmt/tools/api_discovery_tool.py`
- Create: `workers/config_mgmt/tools/http_method_tester.py`
- Create: `workers/config_mgmt/tools/hsts_tester.py`
- Create: `workers/config_mgmt/tools/rpc_tester.py`
- Create: `workers/config_mgmt/tools/file_inclusion_tester.py`
- Create: `workers/config_mgmt/tools/subdomain_takeover_checker.py`
- Create: `workers/config_mgmt/tools/cloud_storage_auditor.py`

**Step 1: Implement each tool class**

Subclass ConfigMgmtTool, implement `build_command()` and `parse_output()` for recon tools.

**Test:** Each tool can be instantiated and has required methods.

---

## Task 4: Configure Concurrency

**Files:**
- Modify: `workers/config_mgmt/concurrency.py`

**Step 1: Set tool weights**

LIGHT for most, HEAVY for Ffuf.

**Test:** Concurrency settings match expectations.

---

## Task 5: Implement Pipeline

**Files:**
- Modify: `workers/config_mgmt/pipeline.py`

**Step 1: Define 11 stages**

Order the tools as listed in the stages table.

**Test:** Pipeline runs without errors (mock tools if needed).

---

## Task 6: Update Main Entry Point

**Files:**
- Modify: `workers/config_mgmt/main.py`

**Step 1: Integrate with lib_webbh messaging**

Listen to recon_queue or appropriate stream.

**Test:** Main can start and listen.

---

## Task 7: Build Docker Image

**Files:**
- Modify: `workers/config_mgmt/Dockerfile`

**Step 1: Add required binaries**

Include ffuf and other tools.

**Test:** Docker build succeeds.

---

## Task 8: Update Docker Compose

**Files:**
- Modify: `docker-compose.yml`

**Step 1: Add config_mgmt service**

**Test:** Compose up starts the worker.

---

## Task 9: Add Tests

**Files:**
- Create: `tests/test_workers/test_config_mgmt/`
- Create: `tests/test_workers/test_config_mgmt/test_pipeline.py`
- Create: `tests/test_workers/test_config_mgmt/test_tools.py`

**Step 1: Write integration tests**

Test pipeline execution and tool outputs.

**Test:** Tests pass.

---

## Task 10: Update Documentation

**Files:**
- Modify: `README.md` or relevant docs

**Step 1: Document the new worker**

**Test:** Docs are updated.