## Coherence Check Report

**Task:** "I renamed the `url` field to `endpoint_url` on the Asset model. Make sure everything is consistent."
**Date:** 2026-05-16
**Branch:** main

Changed files: 0 (rename is hypothetical — not present in git diff)
Checks performed: 28
Issues: 5 total — 0 auto-fixed, 5 need manual review

---

### Phase 1 — Change Discovery

`git diff HEAD~1 --name-only` shows no changes to `shared/lib_webbh/database.py`, `shared/schema.sql`, or any worker/dashboard file related to this rename. The rename from `url` to `endpoint_url` on the `Asset` model was **not found in the git history or working tree**.

**Finding:** The `Asset` ORM model (`shared/lib_webbh/database.py`, class `Asset`, lines 233–266) has **never contained a `url` field**. Assets store URL-typed entries using:
- `asset_type = "url"` (a string enum value stored in the `asset_type` column, not a separate column)
- `asset_value` (the actual URL string, VARCHAR(500))

The field name `url` does not exist on `Asset`. Therefore the rename cannot be "complete" — it was never started, or the task description conflates `asset_type = "url"` (a value) with a hypothetical dedicated `url` column.

**Closest real candidates for confusion:**
- `CloudAsset.url` — a real column (`String(1000)`, nullable) in `database.py:329` and `schema.sql:131`, used consistently for cloud resources only.
- `Parameter.source_url` — a real column (`Text`, nullable) in `database.py:348` and `schema.sql:149`.
- 25+ worker files query `Asset.asset_type == "url"` to filter URL-typed assets.

---

### Auto-Fixed

None. No unambiguous rename was found to apply.

---

### Needs Manual Review

**[MISMATCH-1] `shared/schema.sql` `assets` table is missing 3 columns present in the ORM `Asset` model**

The `Asset` ORM model (`shared/lib_webbh/database.py:233–266`) defines columns absent from `shared/schema.sql:57–72`:

| ORM column | Type | Present in schema.sql |
|---|---|---|
| `scope_classification` | `VARCHAR(20) DEFAULT 'pending'` | No |
| `associated_with_id` | `INTEGER FK → assets.id` | No |
| `association_method` | `VARCHAR(50)` | No |

Actively used by workers:
- `workers/info_gathering/base_tool.py:111` writes `scope_classification=scope_classification`
- `workers/info_gathering/main.py:94` filters `Asset.scope_classification.in_(["in-scope", "associated"])`
- `workers/info_gathering/pipeline.py:375–377` writes `asset.scope_classification` and `asset.association_method`

**Action required:** Add an Alembic migration and update `shared/schema.sql` to add these 3 columns to the `assets` table.

---

**[MISMATCH-2] `shared/schema.sql` `job_state` table is missing `last_completed_stage` column**

The `JobState` ORM model (`shared/lib_webbh/database.py:408`) defines `last_completed_stage: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)` but the `job_state` DDL in `shared/schema.sql:200–221` has no such column. `dashboard/src/types/schema.ts:145` references it as `last_completed_stage: string | null`.

**Action required:** Add an Alembic migration and add `last_completed_stage VARCHAR(100)` to `shared/schema.sql`.

---

**[MISMATCH-3] `shared/interfaces.ts` `Asset` interface is missing newer ORM fields**

`shared/interfaces.ts:54–60` defines `Asset` with only `id`, `target_id`, `asset_type`, `asset_value`, `source_tool` — missing `tech`, `scope_classification`, `associated_with_id`, `association_method`.

`dashboard/src/types/schema.ts:75–82` adds `tech` but still lacks `scope_classification`, `associated_with_id`, `association_method`.

The most complete definition is `dashboard/src/lib/api.ts:83–106` (`AssetWithLocations`), which includes `scope_classification`, `associated_with_id`, `association_method`.

**Action required:** Update `shared/interfaces.ts` and `dashboard/src/types/schema.ts` `Asset` interfaces to include all ORM columns.

---

**[MISMATCH-4] Clarification needed: does the rename target the `asset_type` value "url" or a column?**

If the intent is to rename the *value* `"url"` → `"endpoint_url"` in the `asset_type` enum, this would require changes in 25+ places:

Representative affected files:
- `workers/business_logic/tools/` — 9 files (lines ~55–58 each): `Asset.asset_type == "url"`
- `workers/cryptography/tools/padding_oracle_tester.py:29`, `plaintext_leak_scanner.py:29`
- `workers/error_handling/tools/error_prober.py:33`, `stack_trace_detector.py:33` (raw SQL)
- `workers/info_gathering/tools/` — 14+ files: `asset_type == "url"`, `asset_type = "url"` saves
- `workers/input_validation/base_tool.py:263`
- `workers/mobile_worker/base_tool.py:129`
- `dashboard/src/types/schema.ts:30` `AssetType` union (currently includes `"url"`)
- `shared/interfaces.ts:18` `AssetType` union
- Existing database rows with `asset_type = 'url'` (requires a data migration)

**Action required:** Clarify whether the rename targets an enum value or a column. If enum value `"url"` → `"endpoint_url"` is intended, a phased migration is required — this cannot be auto-fixed.

---

**[MISMATCH-5] `CloudAsset.url` — verify not confused with Asset rename (informational)**

`CloudAsset` has a real `url` column that is consistent across all layers:
- `database.py:329` (ORM)
- `schema.sql:131` (DDL)
- `shared/interfaces.ts:93` (TypeScript)
- `dashboard/src/types/schema.ts:115` (TypeScript)
- `orchestrator/main.py:1448,1909` (serialization)
- `dashboard/src/app/campaign/cloud/page.tsx:217–222` (rendering)
- `dashboard/src/app/campaign/assets/page.tsx:969` (rendering)

No action needed — noted to confirm it was not confused with the hypothetical `Asset.url` rename.

---

### Verified Clean

- `shared/lib_webbh/database.py` `Asset` model — no `url` field exists or ever existed; `asset_value` stores URL strings
- `shared/schema.sql` `assets` table — no `url` column (consistent with ORM on this point)
- `shared/interfaces.ts` `Asset` interface — no `url` field
- `dashboard/src/types/schema.ts` `Asset` interface — no `url` field
- `dashboard/src/lib/api.ts` `AssetWithLocations` — no `url` field
- `CloudAsset.url` across all layers — fully consistent
- `Parameter.source_url` — consistent across all layers
- Worker imports of `Asset` from `lib_webbh` — all use `asset_value` and `asset_type` correctly
- No `endpoint_url` string found anywhere in workers, orchestrator, shared lib, or dashboard

---

### Coverage

Checked:
- `shared/lib_webbh/database.py` — Asset, CloudAsset, Parameter, JobState ORM models
- `shared/schema.sql` — assets, cloud_assets, parameters, job_state DDL
- `shared/interfaces.ts` — Asset, CloudAsset, Parameter TypeScript interfaces
- `dashboard/src/types/schema.ts` — Asset, CloudAsset, AssetType, JobState interfaces
- `dashboard/src/lib/api.ts` — AssetWithLocations, CloudAssetsResponse interfaces
- `dashboard/src/app/campaign/assets/page.tsx` — field access patterns
- `dashboard/src/app/campaign/cloud/page.tsx` — cloud asset url access
- `dashboard/src/app/campaign/findings/page.tsx` — asset/cloud field access
- `dashboard/src/components/c2/AssetDetailDrawer.tsx` — asset_value access
- `orchestrator/main.py` — CloudAsset.url serialization (lines 1448, 1909)
- `workers/business_logic/tools/*.py` — 9 files
- `workers/cryptography/tools/*.py` — 2 files
- `workers/error_handling/tools/*.py` — 2 files (raw SQL)
- `workers/info_gathering/base_tool.py`, `main.py`, `pipeline.py`
- `workers/info_gathering/tools/*.py` — 14+ files
- `workers/input_validation/base_tool.py`
- `workers/mobile_worker/base_tool.py`
- git diff, git log for change baseline
