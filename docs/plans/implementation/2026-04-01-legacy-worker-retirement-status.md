# Legacy Worker Retirement Status

**Last updated:** 2026-04-01
**Phase:** M11 (Cleanup & Retirement) — DEFERRED
**Design doc:** `docs/plans/design/2026-03-29-restructure-12-migration.md`
**Implementation plan:** `docs/plans/implementation/2026-03-29-restructure-m11-cleanup.md`

---

## Current Status

M11 is **DEFERRED** until all migration phases M1–M10 are functionally complete and validated. The legacy workers listed below remain in the codebase and are fully operational during the migration period.

---

## Legacy Worker Inventory

| Legacy Worker | Replacement | Status | docker-compose Service | Dockerfile |
|---|---|---|---|---|
| `workers/recon_core/` | `workers/info_gathering/` | ACTIVE — do not remove | `recon-core` | `docker/Dockerfile.recon` |
| `workers/network_worker/` | `workers/config_mgmt/` (partial) | ACTIVE — do not remove | `network-worker` | `docker/Dockerfile.network` |
| `workers/fuzzing_worker/` | `workers/config_mgmt/` + `workers/input_validation/` | ACTIVE — do not remove | `fuzzing-worker` | `docker/Dockerfile.fuzzing` |
| `workers/cloud_worker/` | `workers/config_mgmt/` | ACTIVE — do not remove | `cloud-worker` | `docker/Dockerfile.cloud` |
| `workers/webapp_worker/` | `workers/input_validation/` | ACTIVE — do not remove | `webapp-worker` | `docker/Dockerfile.webapp` |
| `workers/api_worker/` | `workers/input_validation/` | ACTIVE — do not remove | `api-worker` | `docker/Dockerfile.api` |
| `workers/vuln_scanner/` | `workers/input_validation/` | ACTIVE — do not remove | `vuln-scanner` | `docker/Dockerfile.vulnscanner` |

### Rationale for Retention

1. **Backward compatibility** — Existing campaigns and test suites may still reference old worker names and Redis streams
2. **Parallel operation** — The event engine (M3) is designed to dispatch to both old and new workers during migration
3. **Rollback safety** — If a new worker has issues, the old worker can handle the workload
4. **Data migration** — Old `job_state` records reference old worker types; these must be remapped before deletion
5. **Redis streams** — Old queue streams (`recon_queue`, `fuzzing_queue`, etc.) must be drained before deletion

---

## M11 Gating Criteria

M11 **MUST NOT** begin until ALL of the following are true:

### Functional Completeness

- [ ] **M1** — All new database models, columns, indexes, and Alembic migrations applied and verified
- [ ] **M2** — Proxy and callback services running and passing integration tests
- [ ] **M3** — Event engine dispatching workers correctly with dependency resolution and resource guard
- [ ] **M4** — Info gathering worker running all 10 stages with all 24 tools producing output
- [ ] **M5** — Config management worker running all 11 stages with all 11 tools
- [ ] **M6** — All four credential-dependent workers (identity_mgmt, authentication, authorization, session_mgmt) functional with credential loading, skip logic, and safety policies
- [ ] **M7** — Input validation worker running all stages with all tools (including callback server and proxy integration)
- [ ] **M8** — All four workers (error_handling, cryptography, business_logic, client_side) functional with BrowserManager and proxy/callback integration
- [ ] **M9** — Chain worker creating chain findings and reporting worker producing Markdown reports
- [ ] **M10** — Dashboard rendering all new views (campaign creator, pipeline grid, findings, chains, reports, live terminal)

### Test Validation

- [ ] Full test suite passes: `pytest --tb=short` — zero failures
- [ ] All new worker test directories populated and passing
- [ ] No test imports reference old worker directories
- [ ] E2E campaign against controlled test target (DVWA/WebGoat) completes successfully

### Operational Validation

- [ ] `docker compose up --build` starts all 29 services without errors
- [ ] All new worker containers reach healthy state
- [ ] Campaign created via API runs through full worker pipeline
- [ ] Findings stored with correct `section_id` values
- [ ] Reports generated and exportable
- [ ] No code references to old worker names outside `docs/` and `scripts/`

---

## M11 Execution Checklist

When all gating criteria are met, execute M11 in this order:

1. **Verify operational** — Run test suite, verify all new workers start, grep for old references
2. **Remove old worker directories** — Delete 7 legacy worker dirs + associated test dirs
3. **Remove old Dockerfiles** — Delete 7 legacy Dockerfiles + remove from docker-compose.yml
4. **Remove retired tool configs** — Nuclei, Gauplus, Chaos, Knockpy references
5. **Run Redis stream cleanup** — Execute `scripts/migrate_redis_streams.py`
6. **Run job state migration** — Execute `scripts/migrate_job_state.py`
7. **Update CLAUDE.md** — Reflect new architecture
8. **Final verification** — Tests pass, no old references, docker compose valid

See `docs/plans/implementation/2026-03-29-restructure-m11-cleanup.md` for detailed step-by-step instructions.

---

## Rollback Strategy

If M11 is started and issues are discovered:

1. **Before worker directory deletion** — Simply revert the git commit
2. **After worker directory deletion** — Restore from git history (`git checkout HEAD~1 -- workers/`)
3. **After Dockerfile deletion** — Restore from git history
4. **After Redis stream cleanup** — Streams cannot be recovered; ensure backup exists
5. **After job state migration** — Reverse the UPDATE statements (old_name ← new_name)

**After M11 is complete and pushed, rollback requires restoring from a database backup.**
