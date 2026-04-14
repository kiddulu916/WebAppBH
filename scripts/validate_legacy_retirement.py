#!/usr/bin/env python3
"""Legacy Worker Retirement Validation Harness.

Checks the M11 gating criteria from:
  docs/plans/implementation/2026-04-01-legacy-worker-retirement-status.md

Run:  python scripts/validate_legacy_retirement.py

Exit codes:
  0 — all checks pass, safe to begin M11
  1 — one or more checks failed, M11 must wait
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent

LEGACY_WORKERS = {
    "recon_core":      {"replacement": "info_gathering",   "dockerfile": "Dockerfile.recon",       "service": "recon-core"},
    "network_worker":  {"replacement": "config_mgmt",      "dockerfile": "Dockerfile.network",     "service": "network-worker"},
    "fuzzing_worker":  {"replacement": "config_mgmt",      "dockerfile": "Dockerfile.fuzzing",     "service": "fuzzing-worker"},
    "cloud_worker":    {"replacement": "config_mgmt",      "dockerfile": "Dockerfile.cloud",       "service": "cloud-worker"},
    "webapp_worker":   {"replacement": "input_validation",  "dockerfile": "Dockerfile.webapp",      "service": "webapp-worker"},
    "api_worker":      {"replacement": "input_validation",  "dockerfile": "Dockerfile.api",         "service": "api-worker"},
    "vuln_scanner":    {"replacement": "input_validation",  "dockerfile": "Dockerfile.vulnscanner", "service": "vuln-scanner"},
}

NEW_WORKERS = [
    "info_gathering", "config_mgmt", "identity_mgmt", "authentication",
    "authorization", "session_mgmt", "input_validation", "error_handling",
    "cryptography", "business_logic", "client_side", "chain_worker",
    "reporting_worker",
]

# Directories excluded from "old reference" grep
EXCLUDE_DIRS = {"docs", "scripts", ".git", "__pycache__", "node_modules", ".next", ".worktrees", ".claude"}

# Test files that specifically test legacy workers (will be removed alongside workers during M11).
# These are excluded from import/reference checks because they are expected to reference old workers.
LEGACY_TEST_FILES = {
    "tests/test_recon_pipeline.py",
    "tests/test_recon_base_tool.py",
    "tests/test_recon_concurrency.py",
    "tests/test_recon_integration.py",
    "tests/test_recon_main.py",
    "tests/test_recon_tools_active.py",
    "tests/test_recon_tools_deep.py",
    "tests/test_recon_tools_fingerprinting.py",
    "tests/test_recon_tools_liveness.py",
    "tests/test_recon_tools_passive.py",
    "tests/test_recon_tools_ports.py",
    "tests/test_recon_tools_takeover.py",
    "tests/test_fuzzing_pipeline.py",
    "tests/test_fuzzing_tools.py",
    "tests/test_network_worker_pipeline.py",
    "tests/test_network_worker_tools.py",
    "tests/test_cloud_worker_pipeline.py",
    "tests/test_cloud_worker_tools.py",
    "tests/test_webapp_pipeline.py",
    "tests/test_webapp_integration.py",
    "tests/test_webapp_tools.py",
    "tests/test_api_worker_pipeline.py",
    "tests/test_api_worker_tools.py",
    "tests/test_playbook_pipeline.py",
    "tests/e2e/test_worker_pipelines.py",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class Check:
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.detail = ""

    def ok(self, detail: str = ""):
        self.passed = True
        self.detail = detail

    def fail(self, detail: str):
        self.passed = False
        self.detail = detail


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd or ROOT)


def heading(text: str):
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}")


def report(checks: list[Check]):
    passed = sum(1 for c in checks if c.passed)
    total = len(checks)
    for c in checks:
        icon = "\033[92mPASS\033[0m" if c.passed else "\033[91mFAIL\033[0m"
        print(f"  [{icon}] {c.name}")
        if c.detail:
            for line in c.detail.splitlines():
                print(f"         {line}")
    print(f"\n  {passed}/{total} checks passed")
    return passed == total


# ---------------------------------------------------------------------------
# Checks — Functional Completeness
# ---------------------------------------------------------------------------
def check_new_worker_dirs() -> list[Check]:
    """Verify all replacement worker directories exist with required files."""
    checks = []
    for worker in NEW_WORKERS:
        c = Check(f"New worker directory: workers/{worker}/")
        worker_dir = ROOT / "workers" / worker
        if not worker_dir.is_dir():
            c.fail(f"Directory missing: {worker_dir}")
        else:
            has_main = (worker_dir / "main.py").exists()
            has_pipeline = (worker_dir / "pipeline.py").exists()
            has_tools = (worker_dir / "tools").is_dir() or (worker_dir / "renderers").is_dir()
            missing = []
            if not has_main:
                missing.append("main.py")
            if not has_pipeline:
                missing.append("pipeline.py")
            if not has_tools:
                missing.append("tools/ or renderers/")
            if missing:
                c.fail(f"Missing: {', '.join(missing)}")
            else:
                tools_dir = worker_dir / "tools" if (worker_dir / "tools").is_dir() else worker_dir / "renderers"
                tool_count = len(list(tools_dir.glob("*.py")))
                c.ok(f"{tool_count} tool files")
        checks.append(c)
    return checks


def check_new_worker_dockerfiles() -> list[Check]:
    """Verify Dockerfiles exist for all new workers."""
    checks = []
    docker_dir = ROOT / "docker"
    expected_dockerfiles = {
        "info_gathering": "Dockerfile.info_gathering",
        "config_mgmt": "Dockerfile.config_mgmt",
        "identity_mgmt": "Dockerfile.identity",
        "authentication": "Dockerfile.auth",
        "authorization": "Dockerfile.authz",
        "session_mgmt": "Dockerfile.session_mgmt",
        "input_validation": "Dockerfile.input_validation",
        "error_handling": "Dockerfile.error_handling",
        "cryptography": "Dockerfile.cryptography",
        "business_logic": "Dockerfile.business_logic",
        "client_side": "Dockerfile.client_side",
        "chain_worker": "Dockerfile.chain",
        "reporting_worker": "Dockerfile.reporting",
    }
    for worker, dockerfile in expected_dockerfiles.items():
        c = Check(f"Dockerfile: docker/{dockerfile}")
        path = docker_dir / dockerfile
        if path.exists():
            c.ok()
        else:
            c.fail(f"Missing: {path}")
        checks.append(c)
    return checks


def check_legacy_workers_still_present() -> list[Check]:
    """Verify legacy workers are still present (should be until M11 executes)."""
    checks = []
    for name, info in LEGACY_WORKERS.items():
        c = Check(f"Legacy worker present: workers/{name}/")
        worker_dir = ROOT / "workers" / name
        if worker_dir.is_dir():
            c.ok()
        else:
            c.fail(f"Already removed — M11 may have started prematurely")
        checks.append(c)
    return checks


# ---------------------------------------------------------------------------
# Checks — Test Validation
# ---------------------------------------------------------------------------
def check_test_suite() -> list[Check]:
    """Run pytest and verify zero failures."""
    c = Check("Test suite passes (pytest)")
    result = run([sys.executable, "-m", "pytest", "--tb=line", "-q", "--no-header"], cwd=ROOT)
    # Parse output for pass/fail counts
    last_line = result.stdout.strip().split("\n")[-1] if result.stdout.strip() else ""
    if result.returncode == 0:
        c.ok(last_line)
    else:
        fail_count = ""
        match = re.search(r"(\d+) failed", last_line)
        if match:
            fail_count = f"{match.group(1)} failures"
        c.fail(f"Tests failed: {fail_count or last_line}")
    return [c]


def check_new_worker_tests() -> list[Check]:
    """Verify test files exist for new workers."""
    checks = []
    tests_dir = ROOT / "tests"
    for worker in NEW_WORKERS:
        c = Check(f"Tests exist: {worker}")
        # Check both flat and nested patterns
        flat_pattern = f"test_{worker}*.py"
        nested_dir = tests_dir / f"test_{worker}"
        nested_workers = tests_dir / "test_workers" / f"test_{worker}"

        flat_matches = list(tests_dir.glob(flat_pattern))
        has_nested = nested_dir.is_dir()
        has_workers_nested = nested_workers.is_dir()

        if flat_matches or has_nested or has_workers_nested:
            locations = []
            if flat_matches:
                locations.extend(f.name for f in flat_matches)
            if has_nested:
                locations.append(f"test_{worker}/")
            if has_workers_nested:
                locations.append(f"test_workers/test_{worker}/")
            c.ok(", ".join(locations))
        else:
            c.fail(f"No test files matching test_{worker}* or test_{worker}/ or test_workers/test_{worker}/")
        checks.append(c)
    return checks


def check_no_test_imports_old_workers() -> list[Check]:
    """Ensure no NEW test files import from old worker directories.

    Legacy test files (LEGACY_TEST_FILES) are excluded — they will be removed
    alongside the old workers during M11 execution.
    """
    c = Check("No test imports reference old worker dirs")
    tests_dir = ROOT / "tests"
    violations = []
    old_worker_names = list(LEGACY_WORKERS.keys())

    for test_file in tests_dir.rglob("*.py"):
        rel = str(test_file.relative_to(ROOT))
        if rel in LEGACY_TEST_FILES:
            continue
        try:
            content = test_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        for old_name in old_worker_names:
            # Match imports like: from workers.recon_core or import workers.recon_core
            if re.search(rf"\bworkers\.{old_name}\b", content):
                violations.append(f"{rel} references workers.{old_name}")

    if violations:
        c.fail("\n".join(violations[:10]))
    else:
        c.ok()
    return [c]


# ---------------------------------------------------------------------------
# Checks — Operational Validation
# ---------------------------------------------------------------------------
def check_docker_compose_valid() -> list[Check]:
    """Verify docker-compose.yml parses without errors."""
    c = Check("docker-compose.yml is valid")
    result = run(["docker", "compose", "config", "--quiet"], cwd=ROOT)
    if result.returncode == 0:
        c.ok()
    else:
        # Try docker-compose (v1) as fallback
        result2 = run(["docker-compose", "config", "--quiet"], cwd=ROOT)
        if result2.returncode == 0:
            c.ok()
        else:
            c.fail(result.stderr[:200] if result.stderr else "Parse error")
    return [c]


def check_new_workers_in_compose() -> list[Check]:
    """Verify new workers are defined in docker-compose.yml."""
    c = Check("New workers defined in docker-compose.yml")
    compose_path = ROOT / "docker-compose.yml"
    if not compose_path.exists():
        c.fail("docker-compose.yml not found")
        return [c]

    content = compose_path.read_text()
    missing = []
    for worker in NEW_WORKERS:
        # Service names use hyphens
        service_name = worker.replace("_", "-")
        # Check if service is defined (look for service name at start of line under services)
        if service_name not in content and worker not in content:
            missing.append(worker)

    if missing:
        c.fail(f"Missing services: {', '.join(missing)}")
    else:
        c.ok(f"All {len(NEW_WORKERS)} new workers found")
    return [c]


def check_no_old_references_in_code() -> list[Check]:
    """Grep for old worker names in non-excluded code directories."""
    c = Check("No code references to old worker names (outside docs/scripts)")
    violations = []

    for old_name in LEGACY_WORKERS:
        # Use grep to find references, excluding certain directories
        result = run([
            "grep", "-rl", "--include=*.py", "--include=*.ts", "--include=*.tsx",
            old_name, str(ROOT),
        ])
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                rel = Path(line).relative_to(ROOT)
                rel_str = str(rel)
                parts = rel.parts
                # Skip excluded directories
                if parts and parts[0] in EXCLUDE_DIRS:
                    continue
                # Skip the legacy worker directories themselves (expected)
                if len(parts) >= 2 and parts[0] == "workers" and parts[1] == old_name:
                    continue
                # Skip legacy dockerfiles (expected)
                if len(parts) >= 2 and parts[0] == "docker":
                    dockerfile = LEGACY_WORKERS[old_name].get("dockerfile", "")
                    if parts[1] == dockerfile:
                        continue
                # Skip legacy test files (will be removed during M11)
                if rel_str in LEGACY_TEST_FILES:
                    continue
                violations.append(f"{rel} references '{old_name}'")

    if violations:
        # Dedupe and limit
        unique = sorted(set(violations))
        c.fail(f"{len(unique)} references found:\n" + "\n".join(unique[:15]))
    else:
        c.ok()
    return [c]


def check_migration_scripts_exist() -> list[Check]:
    """Verify cleanup scripts are ready."""
    checks = []
    scripts = [
        ("Redis stream migration", "scripts/migrate_redis_streams.py"),
        ("Job state migration", "scripts/migrate_job_state.py"),
    ]
    for name, path in scripts:
        c = Check(f"Migration script: {path}")
        full_path = ROOT / path
        if full_path.exists():
            c.ok()
        else:
            c.fail("Script not found")
        checks.append(c)
    return checks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("\n" + "=" * 60)
    print("  Legacy Worker Retirement Validation Harness")
    print("  M11 Gating Criteria Check")
    print("=" * 60)

    all_checks: list[Check] = []

    # --- Functional Completeness ---
    heading("Functional Completeness — New Worker Infrastructure")
    checks = check_new_worker_dirs()
    all_checks.extend(checks)
    report(checks)

    heading("Functional Completeness — New Worker Dockerfiles")
    checks = check_new_worker_dockerfiles()
    all_checks.extend(checks)
    report(checks)

    heading("Legacy Workers Still Present (pre-M11)")
    checks = check_legacy_workers_still_present()
    all_checks.extend(checks)
    report(checks)

    # --- Test Validation ---
    heading("Test Validation — Test Suite")
    checks = check_test_suite()
    all_checks.extend(checks)
    report(checks)

    heading("Test Validation — New Worker Test Coverage")
    checks = check_new_worker_tests()
    all_checks.extend(checks)
    report(checks)

    heading("Test Validation — No Old Worker Imports in Tests")
    checks = check_no_test_imports_old_workers()
    all_checks.extend(checks)
    report(checks)

    # --- Operational Validation ---
    heading("Operational Validation — Docker Compose")
    checks = check_docker_compose_valid()
    all_checks.extend(checks)
    report(checks)

    heading("Operational Validation — New Workers in Compose")
    checks = check_new_workers_in_compose()
    all_checks.extend(checks)
    report(checks)

    heading("Operational Validation — Old Worker References in Code")
    checks = check_no_old_references_in_code()
    all_checks.extend(checks)
    report(checks)

    heading("Operational Validation — Migration Scripts Ready")
    checks = check_migration_scripts_exist()
    all_checks.extend(checks)
    report(checks)

    # --- Summary ---
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)

    passed = sum(1 for c in all_checks if c.passed)
    failed = sum(1 for c in all_checks if not c.passed)
    total = len(all_checks)

    if failed == 0:
        print(f"\n  \033[92mALL {total} CHECKS PASSED\033[0m")
        print("  M11 (Legacy Worker Retirement) is SAFE to begin.")
    else:
        print(f"\n  \033[91m{failed}/{total} CHECKS FAILED\033[0m")
        print("  M11 must WAIT until all checks pass.")
        print("\n  Failed checks:")
        for c in all_checks:
            if not c.passed:
                print(f"    - {c.name}")

    print()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
