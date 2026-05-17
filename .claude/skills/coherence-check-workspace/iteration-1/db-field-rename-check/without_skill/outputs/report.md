# Coherence Check: Asset Model `url` -> `endpoint_url` Field Rename

**Date:** 2026-05-16
**Task:** Verify that renaming the `url` field to `endpoint_url` on the Asset model has been consistently applied across the entire codebase.

---

## Executive Summary

**The rename has NOT been applied.** The Asset ORM model in `shared/lib_webbh/database.py` does **not** have a `url` field at all -- it never did. The `url` column that exists in the codebase belongs exclusively to the `CloudAsset` model and its corresponding `cloud_assets` table. The `Asset` model stores its URL-like values in `asset_value` (a generic string column). There is no `endpoint_url` field anywhere in the actual source code (Python, TypeScript, SQL).

The rename either was never applied, was applied to the wrong model, or the task description reflects a planned change that has not yet been implemented.

---

## Findings by Layer

### 1. ORM Model -- `shared/lib_webbh/database.py`

**Current Asset model columns (lines 243-255):**

    id, target_id, asset_type, asset_value, source_tool, tech,
    scope_classification, associated_with_id, association_method

- No `url` column exists on `Asset`.
- No `endpoint_url` column exists on `Asset`.
- URL data is stored in the generic `asset_value: Mapped[str]` column.
- The `url` field **does** exist on `CloudAsset` -- a separate model for cloud resources, unrelated to `Asset`.

**Verdict:** No rename applied; no `url` field existed on `Asset` to rename.

---

### 2. Database Schema -- `shared/schema.sql`

The `assets` table definition (lines 57-72) contains:

    CREATE TABLE IF NOT EXISTS assets (
        id          SERIAL PRIMARY KEY,
        target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        asset_type  VARCHAR(50)  NOT NULL,
        asset_value VARCHAR(500) NOT NULL,
        source_tool VARCHAR(100),
        tech        JSONB,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );

- No `url` column.
- No `endpoint_url` column.
- The `url VARCHAR(1000)` column (line 131) is in the `cloud_assets` table, not `assets`.

**Verdict:** Schema does not reflect any rename. No `url` on `assets`; no `endpoint_url` anywhere.

---

### 3. Alembic Migrations -- `shared/lib_webbh/alembic/versions/001_m1_initial_restructure.py`

The only migration adds `tech` (JSON) to the `assets` table. It never adds or renames a `url` / `endpoint_url` column on `assets`.

**Verdict:** No migration exists for this rename.

---

### 4. TypeScript Interface -- `shared/interfaces.ts`

    export interface Asset extends Timestamps {
      id: number;
      target_id: number;
      asset_type: AssetType;
      asset_value: string;
      source_tool: string | null;
    }

- No `url` field on the `Asset` interface.
- No `endpoint_url` field.
- The `CloudAsset` interface (lines 88-96) **does** have `url: string | null` -- which matches the `cloud_assets` table correctly.

**Verdict:** TypeScript interface does not reflect the rename; no `url` on `Asset` to rename.

---

### 5. Workers (18 active workers)

All workers access URL data via `asset.asset_value`, `Asset.asset_value`, or local variables named `url` (Python variable names, not model attributes). No worker reads `asset.url` or `asset.endpoint_url`.

Representative patterns found:

| File | Pattern | Notes |
|------|---------|-------|
| `workers/info_gathering/tools/attack_surface_analyzer.py:111` | `url = asset.asset_value.lower()` | Reading URL from asset_value |
| `workers/info_gathering/tools/application_mapper.py:93` | `url = asset.asset_value` | Reading URL from asset_value |
| `workers/info_gathering/tools/architecture_modeler.py:48` | `model["urls"].append(asset.asset_value)` | Reading URL from asset_value |
| `workers/input_validation/base_tool.py:263` | `Asset.asset_type == "url"` | Filtering by type string "url" (not a column name) |
| `workers/error_handling/tools/error_prober.py:33` | `SELECT id, asset_value FROM assets WHERE asset_type = 'url'` | Raw SQL, uses asset_value |
| `workers/mobile_worker/base_tool.py:129` | `Asset.asset_type == "url"` | Filtering by type string "url" |

Note: The string "url" appears frequently as a **value** for `asset_type` (e.g., `Asset.asset_type == "url"` or `save_asset(target_id, "url", url, "katana")`). This is the asset type classifier string, not a column name.

**Verdict:** No worker accesses `asset.url` or `asset.endpoint_url`. All URL data flows through `asset_value`. No changes needed or applied.

---

### 6. Orchestrator -- `orchestrator/main.py`

- Line 1448: `"url": ca.url` -- this is `CloudAsset.url`, not `Asset.url`.
- Line 1909: `{"url": c.url}` -- again `CloudAsset.url`.
- No `Asset` instances are serialized with a `url` or `endpoint_url` key.

**Verdict:** No Asset `.url` / `.endpoint_url` usage; `ca.url` references correctly point to `CloudAsset`.

---

### 7. Dashboard -- `dashboard/src/app/`

- `campaign/cloud/page.tsx` lines 217, 220, 222: `asset.url` -- refers to `CloudAsset.url`, not the `Asset` model.
- `campaign/assets/page.tsx`: uses `row.asset_type`, `node.asset_type`, `asset.asset_type` (type string comparisons) -- no `Asset.url` or `Asset.endpoint_url`.
- `campaign/findings/page.tsx` line 159: `c.url` -- `CloudAsset.url`.

**Verdict:** No dashboard code reads `asset.url` or `asset.endpoint_url` from the `Asset` model.

---

### 8. The Only `endpoint_url` Occurrence

A search for `endpoint_url` across the entire codebase (excluding `node_modules` and `.claude`) returned only:

| Location | Content |
|----------|---------|
| `tests/test_info_gathering_stage7.py:434` | Function name `test_analyzer_categorizes_api_endpoint_urls` -- unrelated (test function name, not a model field reference) |
| `.pytest_cache/...` | Cached test ID -- same test function |
| `docs/superpowers/plans/...` | Same test function name in plan document |
| `docs/superpowers/specs/...` | Same test function name in spec document |

No code reads or writes `Asset.endpoint_url` or `asset.endpoint_url` anywhere.

---

## Root Cause Analysis

The `Asset` model has never had a `url` column. The model stores discoverable assets (subdomains, IPs, URLs, CIDRs, forms, websockets, etc.) with a normalized design:

- `asset_type` -- discriminator string (e.g., "url", "subdomain", "ip", "websocket")
- `asset_value` -- the actual value (e.g., "https://example.com/admin")

The `url` column that exists in the codebase belongs to `CloudAsset` (`cloud_assets` table), which models infrastructure-level cloud resources that have a distinct URL field.

The task description "I renamed `url` to `endpoint_url` on the Asset model" appears to describe a rename that either:
1. Was applied to the wrong model (`CloudAsset` has `url`, not `Asset`), or
2. Was never implemented in code -- only described in the task.

---

## Gaps / Inconsistencies Found

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| 1 | `shared/lib_webbh/database.py` | `Asset` model has no `url` field and no `endpoint_url` field -- rename not applied | BLOCKER |
| 2 | `shared/schema.sql` | `assets` table has no `url` column and no `endpoint_url` column | BLOCKER |
| 3 | `shared/lib_webbh/alembic/versions/` | No migration adds `endpoint_url` to `assets` | BLOCKER |
| 4 | `shared/interfaces.ts` | `Asset` TypeScript interface has no `url` or `endpoint_url` field | BLOCKER |
| 5 | All 18 workers | No worker code references `asset.url` or `asset.endpoint_url` | Consistent with model; no gap |
| 6 | `orchestrator/main.py` | `CloudAsset.url` (not `Asset.url`) used correctly | Not a gap |
| 7 | Dashboard `.tsx` files | `CloudAsset.url` used correctly; no `Asset.url` usage | Not a gap |

---

## Recommendation

The rename has not been executed. If the intent is to add an `endpoint_url` field to the `Asset` model (as a dedicated column distinct from the generic `asset_value`), the following changes are required in full:

1. **`shared/lib_webbh/database.py`** -- Add `endpoint_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)` to the `Asset` class.
2. **`shared/schema.sql`** -- Add `endpoint_url VARCHAR(2000)` to the `assets` table DDL.
3. **`shared/lib_webbh/alembic/versions/`** -- Create a new migration that adds the column with `op.add_column("assets", ...)`.
4. **`shared/interfaces.ts`** -- Add `endpoint_url: string | null` to the `Asset` interface.
5. **All workers** -- Update any code that currently reads URL values from `asset_value` to read from `endpoint_url` where appropriate, or update `save_asset()` calls to populate `endpoint_url`.
6. **Dashboard** -- Update any asset display logic to read `endpoint_url` where relevant.

Alternatively, if the rename was intended on `CloudAsset` (which does have a `url` field), all the above targets shift to the `CloudAsset` model and `cloud_assets` table, plus the dashboard cloud pages and orchestrator serialization at `main.py:1448` and `main.py:1909`.
