# Phase 9 — Mobile Worker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Dockerized `mobile_worker` that performs SAST for APK/IPA, targeted Android DAST with Frida on emulator, and feeds discovered in-scope endpoints back into Recon.

**Architecture:** Follow existing worker pattern (`base_tool.py`, `pipeline.py`, `concurrency.py`, `main.py`, `tools/`) used by `workers/api_worker/` and `workers/fuzzing_worker/`. Execute a 5-stage pipeline with static tasks parallelized and dynamic tasks serialized.

**Tech Stack:** Python 3.11, asyncio, SQLAlchemy async, Redis Streams, httpx, apktool, jadx, MobSF REST API, ADB, frida-tools, Docker sidecars.

**Design doc:** `docs/plans/design/2026-03-11-phase9-mobile-worker-design.md`

---

## Task 1: Add `MobileApp` model to shared library

**Files:**
- Modify: `shared/lib_webbh/database.py`
- Modify: `shared/lib_webbh/__init__.py`
- Modify: `tests/test_database.py`

**Step 1: Write failing tests**

Add tests in `tests/test_database.py` for:
- Importability of `MobileApp` from `lib_webbh`.
- CRUD for `MobileApp`.
- Uniqueness on `(target_id, platform, package_name)`.

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_database.py -k "mobile_app" -v`

Expected: failure before model/export exists.

**Step 3: Implement model and relationships**

In `shared/lib_webbh/database.py`:
- Add `MobileApp` with columns from the design doc:
  - `target_id`, `asset_id`, `platform`, `package_name`, `version`, `permissions`, `signing_info`, `mobsf_score`, `decompiled_path`, `source_url`, `source_tool`.
- Add `UniqueConstraint("target_id", "platform", "package_name", name="uq_mobile_apps_target_platform_pkg")`.
- Add relationships:
  - `Target.mobile_apps`
  - `Asset.mobile_apps`

In `shared/lib_webbh/__init__.py`:
- Export `MobileApp` in imports and `__all__`.

**Step 4: Run tests**

Run:
`python -m pytest tests/test_database.py -k "mobile_app" -v`

Expected: pass.

---

## Task 2: Scaffold `workers/mobile_worker/` package and concurrency controls

**Files:**
- Create: `workers/mobile_worker/__init__.py`
- Create: `workers/mobile_worker/tools/__init__.py`
- Create: `workers/mobile_worker/concurrency.py`
- Create: `tests/test_mobile_worker_pipeline.py`

**Step 1: Write failing tests**

Add tests for:
- `WeightClass` enum values.
- `get_semaphores()` default behavior:
  - static semaphore capacity `3`
  - dynamic semaphore capacity `1`

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_mobile_worker_pipeline.py::test_mobile_concurrency_defaults -v`

Expected: `ModuleNotFoundError`.

**Step 3: Implement concurrency module**

In `workers/mobile_worker/concurrency.py`:
- Add `WeightClass` (`STATIC`, `DYNAMIC`).
- Add `get_semaphores(force_new=False)` with env-backed defaults:
  - `MOBILE_STATIC_CONCURRENCY` default `3`
  - `MOBILE_DYNAMIC_CONCURRENCY` default `1`
- Add `get_semaphore(weight)`.

**Step 4: Run tests**

Run:
`python -m pytest tests/test_mobile_worker_pipeline.py -k "concurrency" -v`

Expected: pass.

---

## Task 3: Create `MobileTestTool` base class with DB and worker helpers

**Files:**
- Create: `workers/mobile_worker/base_tool.py`
- Modify: `tests/test_mobile_worker_pipeline.py`

**Step 1: Write failing tests**

Cover:
- `check_cooldown()` behavior with/without prior `JobState`.
- `_save_mobile_app()` upsert by `(target_id, platform, package_name)`.
- `_get_binary_urls()` reads APK/IPA candidates from assets.
- `_scan_drop_folder()` lists files from `/app/shared/mobile_binaries/{target_id}/`.
- `_save_vulnerability()` creates alert for `high`/`critical`.

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_mobile_worker_pipeline.py -k "base_tool" -v`

Expected: failure due to missing base tool.

**Step 3: Implement `base_tool.py`**

Create `MobileTestTool(ABC)` with helpers from design doc:
- `run_subprocess(cmd, timeout)`
- `check_cooldown(target_id, container_name)`
- `update_tool_state(target_id, container_name)`
- `_get_binary_urls(target_id)`
- `_scan_drop_folder(target_id)`
- `_get_mobile_app(target_id, package_name)`
- `_save_mobile_app(...)`
- `_save_asset(...)` with scope-check
- `_save_vulnerability(...)`
- `_create_alert(...)` with Redis/SSE handoff

**Step 4: Run tests**

Run:
`python -m pytest tests/test_mobile_worker_pipeline.py -k "base_tool" -v`

Expected: pass.

---

## Task 4: Build 5-stage mobile pipeline and checkpointing

**Files:**
- Create: `workers/mobile_worker/pipeline.py`
- Modify: `workers/mobile_worker/tools/__init__.py`
- Modify: `tests/test_mobile_worker_pipeline.py`

**Step 1: Write failing tests**

Add tests for:
- Stage order and names:
  1. `acquire_decompile`
  2. `secret_extraction`
  3. `configuration_audit`
  4. `dynamic_analysis`
  5. `endpoint_feedback`
- Resume-from-checkpoint logic using `JobState.current_phase`.
- Result aggregation and exception handling.

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_mobile_worker_pipeline.py -k "pipeline" -v`

Expected: failure before pipeline exists.

**Step 3: Implement pipeline**

In `workers/mobile_worker/pipeline.py`:
- Add stage dataclass/list and stage index mapping.
- Use static semaphore for stages 1-3 and 5.
- Use dynamic semaphore for stage 4 (serialized per emulator).
- Add checkpoint methods (`_get_completed_phase`, `_update_phase`, `_mark_completed`).
- Add `_aggregate_results()`.

**Step 4: Run tests**

Run:
`python -m pytest tests/test_mobile_worker_pipeline.py -k "pipeline" -v`

Expected: pass.

---

## Task 5: Create `main.py` queue listener for `mobile_queue`

**Files:**
- Create: `workers/mobile_worker/main.py`
- Modify: `tests/test_mobile_worker_pipeline.py`

**Step 1: Write failing tests**

Add tests that `handle_message()`:
- Validates target existence.
- Creates/updates `JobState`.
- Instantiates and runs `Pipeline`.
- Handles missing target without crashing.

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_mobile_worker_pipeline.py -k "main_handle_message" -v`

Expected: failure before `main.py` exists.

**Step 3: Implement listener**

In `workers/mobile_worker/main.py`:
- Container naming pattern: `mobile-worker-{hostname}`.
- Queue/group: `mobile_queue` / `mobile_group`.
- Build `ScopeManager` from target profile.
- Call `listen_queue(...)` and dispatch to pipeline.

**Step 4: Run tests**

Run:
`python -m pytest tests/test_mobile_worker_pipeline.py -k "main_handle_message" -v`

Expected: pass.

---

## Task 6: Implement Stage 1 tools (Acquire + Decompile + MobSF)

**Files:**
- Create: `workers/mobile_worker/tools/binary_downloader.py`
- Create: `workers/mobile_worker/tools/apktool_decompiler.py`
- Create: `workers/mobile_worker/tools/mobsf_scanner.py`
- Modify: `workers/mobile_worker/tools/__init__.py`
- Modify: `workers/mobile_worker/pipeline.py`
- Create: `tests/test_mobile_worker_stage1_tools.py`

**Step 1: Write failing tests**

Add focused tests for:
- `binary_downloader`:
  - detects APK/IPA URLs
  - enforces 100MB limit (headers + streaming bytes)
  - supports manual drop folder
- `apktool_decompiler`:
  - command composition for apktool/jadx
  - manifest parsing (`package_name`, version, permissions)
- `mobsf_scanner`:
  - upload/scan/report flow
  - poll timeout (10m)
  - report cache path generation

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_mobile_worker_stage1_tools.py -v`

Expected: failure with missing modules.

**Step 3: Implement tools**

- `binary_downloader.py`:
  - acquire binaries from DB URLs, Play Store (`apkeep` best-effort), and drop folder.
  - save files under `/app/shared/mobile_analysis/{target_id}/`.
- `apktool_decompiler.py`:
  - APK-only decompilation with `apktool d` and `jadx`.
  - persist metadata to `MobileApp`.
- `mobsf_scanner.py`:
  - call MobSF REST endpoints: upload, scan, report.
  - save `mobsf_score` and JSON report artifact.

**Step 4: Wire Stage 1**

Register tool classes in stage 1 within `pipeline.py` and export via `tools/__init__.py`.

**Step 5: Run tests**

Run:
`python -m pytest tests/test_mobile_worker_stage1_tools.py tests/test_mobile_worker_pipeline.py -k "stage1 or pipeline" -v`

Expected: pass.

---

## Task 7: Implement Stage 2 tools (secret extraction)

**Files:**
- Create: `workers/mobile_worker/tools/secret_scanner.py`
- Create: `workers/mobile_worker/tools/mobsf_secrets.py`
- Modify: `workers/mobile_worker/tools/__init__.py`
- Modify: `workers/mobile_worker/pipeline.py`
- Create: `tests/test_mobile_worker_stage2_tools.py`

**Step 1: Write failing tests**

Cover:
- regex extraction for AWS/Firebase/Google keys/password/private key markers.
- severity mapping (`critical` for AWS/private key, `high` otherwise).
- deduplication between local regex findings and MobSF findings by secret value.

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_mobile_worker_stage2_tools.py -v`

Expected: failure before tool modules exist.

**Step 3: Implement tools**

- `secret_scanner.py` scans Jadx source output and creates vulnerabilities.
- `mobsf_secrets.py` parses cached MobSF report JSON and merges without duplicates.

**Step 4: Wire Stage 2 and run tests**

Run:
`python -m pytest tests/test_mobile_worker_stage2_tools.py tests/test_mobile_worker_pipeline.py -k "stage2 or pipeline" -v`

Expected: pass.

---

## Task 8: Implement Stage 3 tools (configuration + deeplink audit)

**Files:**
- Create: `workers/mobile_worker/tools/manifest_auditor.py`
- Create: `workers/mobile_worker/tools/ios_plist_auditor.py`
- Create: `workers/mobile_worker/tools/deeplink_analyzer.py`
- Modify: `workers/mobile_worker/tools/__init__.py`
- Modify: `workers/mobile_worker/pipeline.py`
- Create: `tests/test_mobile_worker_stage3_tools.py`

**Step 1: Write failing tests**

Add tests for:
- Android manifest checks (`allowBackup`, `debuggable`, `usesCleartextTraffic`, `FileProvider` risks).
- iOS ATS and plist checks from MobSF data.
- Deeplink parsing and severity rules for sensitive actions.

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_mobile_worker_stage3_tools.py -v`

Expected: failure before implementation.

**Step 3: Implement tools**

- `manifest_auditor.py` parses decompiled `AndroidManifest.xml`.
- `ios_plist_auditor.py` audits iOS plist fields from MobSF report.
- `deeplink_analyzer.py` inspects Android intent filters and iOS URL schemes/associated domains.

**Step 4: Wire Stage 3 and run tests**

Run:
`python -m pytest tests/test_mobile_worker_stage3_tools.py tests/test_mobile_worker_pipeline.py -k "stage3 or pipeline" -v`

Expected: pass.

---

## Task 9: Implement Stage 4 tools (Frida dynamic analysis, APK only)

**Files:**
- Create: `workers/mobile_worker/tools/frida_crypto_hooker.py`
- Create: `workers/mobile_worker/tools/frida_root_detector.py`
- Create: `workers/mobile_worker/tools/frida_component_prober.py`
- Modify: `workers/mobile_worker/tools/__init__.py`
- Modify: `workers/mobile_worker/pipeline.py`
- Create: `tests/test_mobile_worker_stage4_tools.py`

**Step 1: Write failing tests**

Cover:
- ADB/emulator health-check behavior.
- command lifecycle: install APK, start frida-server, execute scripts, uninstall APK.
- parser logic for key findings from stdout/logcat.
- timeout handling (60s/script) and non-blocking continuation.

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_mobile_worker_stage4_tools.py -v`

Expected: failure before stage 4 modules exist.

**Step 3: Implement tools**

- `frida_crypto_hooker.py`: hook crypto/SSL/pinning/http classes and classify findings.
- `frida_root_detector.py`: hook root/safetynet detection paths and report bypassability.
- `frida_component_prober.py`: probe exported components discovered in stage 3.

All scripts are inline JS in tool files (as per design decision).

**Step 4: Wire Stage 4 and run tests**

Run:
`python -m pytest tests/test_mobile_worker_stage4_tools.py tests/test_mobile_worker_pipeline.py -k "stage4 or pipeline" -v`

Expected: pass.

---

## Task 10: Implement Stage 5 tool (endpoint extraction + recon feedback)

**Files:**
- Create: `workers/mobile_worker/tools/endpoint_extractor.py`
- Modify: `workers/mobile_worker/tools/__init__.py`
- Modify: `workers/mobile_worker/pipeline.py`
- Create: `tests/test_mobile_worker_stage5_tools.py`

**Step 1: Write failing tests**

Add tests for:
- endpoint aggregation from JADX source, MobSF report, and Frida runtime data.
- deduplication rules.
- scope filtering through `ScopeManager`.
- in-scope behavior:
  - upsert into `assets`
  - push task to `recon_queue` with high-priority/source metadata
- out-of-scope behavior: log only.

**Step 2: Run test to confirm failure**

Run:
`python -m pytest tests/test_mobile_worker_stage5_tools.py -v`

Expected: failure before implementation.

**Step 3: Implement tool and wire stage**

Create `endpoint_extractor.py` and add into stage 5.

**Step 4: Run tests**

Run:
`python -m pytest tests/test_mobile_worker_stage5_tools.py tests/test_mobile_worker_pipeline.py -k "stage5 or pipeline" -v`

Expected: pass.

---

## Task 11: Add Docker build/runtime for mobile worker and sidecars

**Files:**
- Create: `docker/Dockerfile.mobile`
- Modify: `docker-compose.yml`

**Step 1: Write Dockerfile**

Create multi-stage `docker/Dockerfile.mobile`:
- builder installs mobile tooling (`apktool`, `jadx`, `apkeep`, `frida-tools`).
- runtime uses slim Python + JRE and copies required binaries.
- install Python deps including `lib_webbh`.
- entrypoint: `python -m workers.mobile_worker.main`.

**Step 2: Add compose services**

In `docker-compose.yml`, add:
- `mobile-worker` service (worker runtime + shared DB/Redis envs).
- `mobsf` sidecar (`opensecurity/mobile-security-framework-mobsf:latest`) with API key env.
- `docker-android` sidecar (`budtmo/docker-android:latest`) with ADB and KVM/privileged config.
- shared volumes:
  - `/app/shared/mobile_analysis/`
  - `/app/shared/mobile_binaries/`

**Step 3: Basic build validation**

Run:
`docker compose build mobile-worker`

If environment supports it, run:
`docker compose up -d mobsf docker-android mobile-worker`

Expected: worker and sidecars start successfully.

---

## Task 12: Final integration checks and regression test pass

**Files:**
- Modify: `tests/test_mobile_worker_pipeline.py`
- Modify: `tests/test_mobile_worker_stage*_tools.py` (as needed)

**Step 1: Add wiring/integration tests**

Add tests that verify:
- all stage tools are wired in correct stages.
- total expected tool count.
- imports for `workers.mobile_worker.tools` succeed.

**Step 2: Run mobile worker test suite**

Run:
`python -m pytest tests/test_mobile_worker_pipeline.py tests/test_mobile_worker_stage1_tools.py tests/test_mobile_worker_stage2_tools.py tests/test_mobile_worker_stage3_tools.py tests/test_mobile_worker_stage4_tools.py tests/test_mobile_worker_stage5_tools.py -v`

Expected: pass.

**Step 3: Run broader regression subset**

Run:
`python -m pytest tests/test_database.py tests/test_recon_pipeline.py tests/test_api_worker_pipeline.py tests/test_fuzzing_pipeline.py -v`

Expected: pass with no regressions.

---

## Notes for execution

- Keep queue/group names fixed to `mobile_queue` and `mobile_group`.
- Keep file-size limit fixed at 100MB for downloaded binaries.
- Keep static/dynamic concurrency split (`3` / `1`) unless changed by env.
- Do not introduce additional DB tables beyond `MobileApp`.
