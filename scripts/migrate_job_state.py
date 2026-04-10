"""
One-time script to remap old worker_type values in job_state table.

Run AFTER the Alembic migration from M1 has been applied
and AFTER all new workers (M1-M10) are operational.

See: docs/plans/implementation/2026-04-01-legacy-worker-retirement-status.md

Usage:
    python scripts/migrate_job_state.py

Environment:
    DB_HOST  — PostgreSQL host (default: localhost)
    DB_PORT  — PostgreSQL port (default: 5432)
    DB_USER  — Database user (default: webbh_admin)
    DB_PASS  — Database password (default: changeme)
    DB_NAME  — Database name (default: webbh)
"""
import asyncio
import os

from sqlalchemy import text

from lib_webbh.database import get_session

WORKER_MAPPING = {
    "recon_core": "info_gathering",
    "network_worker": "config_mgmt",
    "fuzzing_worker": "config_mgmt",
    "cloud_worker": "config_mgmt",
    "webapp_worker": "input_validation",
    "api_worker": "input_validation",
    "vuln_scanner": "input_validation",
}


async def main():
    print("Connecting to database...")
    async with get_session() as session:
        for old_name, new_name in WORKER_MAPPING.items():
            result = await session.execute(
                text(
                    "UPDATE job_state SET container_name = :new WHERE container_name = :old"
                ),
                {"new": new_name, "old": old_name},
            )
            if result.rowcount > 0:
                print(f"  Remapped {result.rowcount} rows: {old_name} -> {new_name}")
            else:
                print(f"  No rows found for: {old_name}")

        await session.commit()

    print("\nJob state migration complete.")


if __name__ == "__main__":
    asyncio.run(main())
