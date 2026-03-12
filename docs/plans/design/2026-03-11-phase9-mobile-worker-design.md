# Phase 9 — Mobile App Testing Worker Design Document

**Date:** 2026-03-11
**Scope:** Phase 9 — Mobile-App-Testing Dockerized worker (SAST + targeted DAST)

## Overview

The Mobile App Testing Worker (`mobile_worker`) performs automated Static Application Security Testing (SAST) and targeted Dynamic Application Security Testing (DAST) on Android APKs and iOS IPAs. It runs as a Docker container alongside two sidecars: **MobSF** (REST API for static analysis) and **`budtmo/docker-android`** (headless Android emulator for Frida dynamic analysis).

### Key Decisions

- **Queue:** `mobile_queue` / `mobile_group`
- **Container name:** `mobile-worker-{hostname}`
- **MobSF integration:** REST API sidecar (not embedded)
- **iOS support:** Basic IPA analysis via MobSF only (no macOS toolchain); custom tools target APK
- **Android emulator:** `budtmo/docker-android` sidecar with KVM passthrough for Frida DAST
- **Frida scripts:** Inline JS in Python tool files (no separate script directory)
- **Binary acquisition:** Direct URL download + `apkeep` for Play Store + manual drop folder
- **New DB table:** `MobileApp` added to `shared/lib_webbh/database.py`
- **Concurrency:** Parallel static (semaphore 3), sequential dynamic (semaphore 1)
- **File size limit:** 100MB per binary

## Directory Layout

```
workers/mobile_worker/
    __init__.py
    base_tool.py              # MobileTestTool(ABC)
    concurrency.py            # WeightClass/semaphore pattern
    pipeline.py               # 5-stage Pipeline class
    main.py                   # Queue listener entry point
    tools/
        __init__.py
        # Stage 1 — Acquire & Decompile
        binary_downloader.py      # URL download + apkeep + drop folder scanner
        apktool_decompiler.py     # Apktool/Jadx decompilation for APKs
        mobsf_scanner.py          # Submit binary to MobSF REST API, poll results
        # Stage 2 — Secret Extraction
        secret_scanner.py         # Regex suite: API keys, Firebase, AWS, hardcoded creds
        mobsf_secrets.py          # Parse MobSF results for secrets it found
        # Stage 3 — Configuration Audit
        manifest_auditor.py       # AndroidManifest: allowBackup, debuggable, FileProvider
        ios_plist_auditor.py      # iOS plist/ATS checks (MobSF-sourced data)
        deeplink_analyzer.py      # URL schemes, intent filters, universal links
        # Stage 4 — Dynamic Frida Analysis
        frida_crypto_hooker.py    # Hook javax.crypto, SSLContext, OkHttp, pinning bypass
        frida_root_detector.py    # Hook RootBeer, SafetyNet, common root checks
        frida_component_prober.py # Launch exported Activities/Services/Receivers
        # Stage 5 — Endpoint Discovery & Feed-back
        endpoint_extractor.py     # Extract URLs/IPs from static + dynamic results
```

## Database — `MobileApp` Model

Added to `shared/lib_webbh/database.py` alongside the existing models:

```python
class MobileApp(TimestampMixin, Base):
    __tablename__ = "mobile_apps"
    __table_args__ = (
        UniqueConstraint("target_id", "platform", "package_name",
                         name="uq_mobile_apps_target_platform_pkg"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    asset_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("assets.id"), nullable=True)
    platform: Mapped[str] = mapped_column(String(10))          # "android" or "ios"
    package_name: Mapped[str] = mapped_column(String(500))      # e.g. "com.target.app"
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    permissions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    signing_info: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    mobsf_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    decompiled_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
```

**Column rationale:**
- `platform` + `package_name` uniquely identify an app per target
- `permissions` — JSON array of declared permissions (Android manifest / iOS entitlements)
- `signing_info` — JSON with certificate details, useful for identifying shared signing across APKs
- `mobsf_score` — MobSF's security score (0-100) for quick triage
- `decompiled_path` — path to decompiled output in `/app/shared/mobile_analysis/`
- `source_url` — where the binary was downloaded from

Relationships added to `Target` (`mobile_apps`) and `Asset` (`mobile_apps`).

## Base Tool — `MobileTestTool(ABC)`

Mirrors `ApiTestTool` with mobile-specific helpers:

- `_get_binary_urls(target_id)` — query assets for `.apk`/`.ipa` links
- `_scan_drop_folder(target_id)` — check `/app/shared/mobile_binaries/{target_id}/`
- `_get_mobile_app(target_id, package_name)` — fetch `MobileApp` row
- `_save_mobile_app(...)` — upsert `MobileApp` row
- `_save_vulnerability(...)` — insert Vulnerability + Alert for critical/high
- `_save_asset(...)` — scope-check and upsert Asset
- `_create_alert(...)` — write alert to DB and push to Redis for SSE
- `run_subprocess(cmd, timeout)` — async subprocess runner
- `check_cooldown(target_id, container_name)` — skip if run within COOLDOWN_HOURS
- `update_tool_state(target_id, container_name)` — update JobState

## 5-Stage Pipeline

### Stage 1 — Acquire & Decompile

**`binary_downloader.py`** — Three acquisition channels:
- Query `assets` table for URLs ending in `.apk`, `.ipa`, `.zip` then download via `httpx` with 100MB size limit (stream + check `Content-Length` header, abort if exceeded)
- Detect `play.google.com` links then shell out to `apkeep` with package ID, best-effort (log warning on failure, don't block pipeline)
- Scan `/app/shared/mobile_binaries/{target_id}/` for manually placed files
- All binaries saved to `/app/shared/mobile_analysis/{target_id}/{filename}`

**`apktool_decompiler.py`** — APK only:
- Run `apktool d` to extract `AndroidManifest.xml`, resources, smali
- Run `jadx` to decompile to Java source for better regex matching
- Output stored at `decompiled_path` in `MobileApp` row
- Parse `AndroidManifest.xml` for package name, version, permissions then populate `MobileApp` columns

**`mobsf_scanner.py`** — APK and IPA:
- Upload binary to MobSF REST API (`/api/v1/upload`)
- Poll `/api/v1/scan` until complete (timeout: 10 minutes)
- Fetch JSON report via `/api/v1/report_json`
- Store `mobsf_score` in `MobileApp` row
- Cache full JSON report to `/app/shared/mobile_analysis/{target_id}/{package_name}_mobsf.json` for Stages 2-3

### Stage 2 — Secret Extraction

**`secret_scanner.py`** — Runs regex suite over Jadx decompiled Java source:
- AWS keys (`AKIA[0-9A-Z]{16}`)
- Firebase URLs (`*.firebaseio.com`, `*.firebaseapp.com`)
- Google API keys (`AIza[0-9A-Za-z_-]{35}`)
- Generic API keys/tokens (configurable pattern list)
- Hardcoded passwords (password assignment patterns)
- Private keys (PEM headers)
- Each match creates a vulnerability with severity based on secret type (AWS/private key = critical, others = high)

**`mobsf_secrets.py`** — Parse MobSF's cached JSON report:
- Extract MobSF's own secret findings (avoids duplicating regex work)
- Deduplicate against `secret_scanner` results by matching on the secret value
- Fill gaps — MobSF catches things our regex might miss (e.g., encoded secrets)

### Stage 3 — Configuration Audit

**`manifest_auditor.py`** — Parse decompiled `AndroidManifest.xml`:
- `android:allowBackup="true"` — high (data exfiltration risk)
- `android:debuggable="true"` — critical (attach debugger in production)
- Insecure `FileProvider` paths exposing root or sdcard — high
- `android:usesCleartextTraffic="true"` — medium
- Missing `android:networkSecurityConfig` — informational
- Exported components without permission guards — logged for Stage 4 probing

**`ios_plist_auditor.py`** — Sourced from MobSF's IPA report:
- App Transport Security exceptions (`NSAllowsArbitraryLoads`) — high
- Missing `NSAppTransportSecurity` dictionary — medium
- Insecure URL schemes in `CFBundleURLTypes` — medium
- Broad entitlements (`com.apple.developer.associated-domains` wildcards) — medium

**`deeplink_analyzer.py`** — Both platforms:
- Android: Parse `<intent-filter>` for custom schemes, `<data>` host/path patterns, `android:autoVerify` status
- iOS: Parse `CFBundleURLTypes` and associated domains from MobSF report
- Flag schemes that accept arbitrary data without validation — high
- Flag deeplinks that trigger sensitive actions (login, payment, account linking) by matching path keywords — high

### Stage 4 — Dynamic Frida Analysis (APK only)

**Emulator setup** per binary:
- Connect to `docker-android` sidecar via ADB (`adb connect emulator:5555`)
- Install APK (`adb install`)
- Push `frida-server` to device, start it
- Launch app's main activity
- Run hook scripts, collect output
- Uninstall APK when done

**`frida_crypto_hooker.py`** — Inline JS hooks for:
- `javax.crypto.Cipher.init/doFinal` — log algorithm, key material, IV
- `javax.net.ssl.SSLContext.init` — detect custom TrustManagers (pinning bypass indicators)
- `okhttp3.CertificatePinner` — log pinned domains and whether bypass is trivial
- `java.net.HttpURLConnection.connect` — capture plaintext HTTP calls
- Each insecure finding becomes a vulnerability (weak crypto = high, no pinning = medium, plaintext HTTP = high)

**`frida_root_detector.py`** — Inline JS hooks for:
- `com.scottyab.rootbeer.RootBeer` methods — force return false, log detection attempt
- `com.google.android.gms.safetynet` — intercept attestation calls
- Common patterns: `Runtime.exec("su")`, file existence checks for `/system/app/Superuser.apk`
- Report whether root detection is present and how easily bypassed — informational/medium

**`frida_component_prober.py`** — Uses exported components found in Stage 3:
- Launch each exported `Activity` via `adb shell am start` with crafted intents
- Bind to exported `Services`, send empty/malformed messages
- Send broadcasts to exported `Receivers`
- Monitor for crashes (logcat), data leaks (Frida network hooks still active), or unauthorized access
- Unprotected component that exposes data or crashes — high/critical

### Stage 5 — Endpoint Discovery & Feed-back

**`endpoint_extractor.py`** — Aggregates from all prior stages:
- Scan Jadx decompiled source for URL/IP regex patterns
- Parse MobSF report's "urls" and "domains" sections
- Collect runtime network calls captured by Frida crypto hooker (Stage 4)
- Deduplicate all discovered endpoints
- Scope-check each via `ScopeManager` — in-scope domains/IPs get:
  - Upserted into `assets` table with `source_tool="endpoint_extractor"`
  - Pushed to `recon_queue` as high-priority recon tasks for Recon-Core
- Out-of-scope endpoints logged but not stored

## Docker Setup

### `Dockerfile.mobile` — Multi-stage build

```
Stage 1 (builder): Install apktool, jadx, apkeep, frida-tools
Stage 2 (runtime): Debian-slim + Python 3.11 + JRE 17
  - Copy tools from builder
  - pip install: frida-tools, httpx, sqlalchemy[asyncpg], lib_webbh
  - ENTRYPOINT: python -m workers.mobile_worker.main
```

### `docker-compose.mobile.yml` — Three services

- `mobile-worker`: Our worker container, connects to shared PostgreSQL/Redis
- `mobsf`: `opensecurity/mobile-security-framework-mobsf:latest`, exposes API on port 8000, env var `MOBSF_API_KEY`
- `docker-android`: `budtmo/docker-android:latest`, `--privileged` with `/dev/kvm` passthrough, ADB on port 5555

Shared volumes:
- `/app/shared/mobile_analysis/` — decompiled output and MobSF reports
- `/app/shared/mobile_binaries/` — manual drop folder

## Resource Control

- **File size limit:** 100MB enforced at download time (streaming check). Binaries exceeding this are logged and skipped.
- **Static concurrency:** `asyncio.Semaphore(3)` for Stages 1-3, 5 — max 3 binaries in parallel
- **Dynamic concurrency:** `asyncio.Semaphore(1)` for Stage 4 — one APK on emulator at a time
- **MobSF timeout:** 10 minutes per binary scan, abort and log on timeout
- **Frida timeout:** 60 seconds per hook script, kill and move on if exceeded
- **Emulator health check:** Ping ADB before Stage 4, skip dynamic analysis if emulator unreachable
