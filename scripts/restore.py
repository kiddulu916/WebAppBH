#!/usr/bin/env python3
"""Restore WebAppBH database and config files from a backup.

Usage:
    python scripts/restore.py <backup_dir>
"""
import os
import subprocess
import shutil
import sys
from pathlib import Path

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "webbh")
DB_USER = os.environ.get("DB_USER", "webbh_admin")
DB_PASS = os.environ.get("DB_PASS", "")


def restore(backup_dir: str) -> None:
    """Restore database and config from a backup directory."""
    backup_path = Path(backup_dir)
    if not backup_path.is_dir():
        print(f"ERROR: Backup directory not found: {backup_dir}")
        sys.exit(1)

    # Restore database
    dump_file = backup_path / "database.sql"
    if dump_file.exists():
        cmd = [
            "psql",
            "-h", DB_HOST,
            "-p", DB_PORT,
            "-U", DB_USER,
            "-d", DB_NAME,
            "-f", str(dump_file),
        ]
        env = {**os.environ, "PGPASSWORD": DB_PASS}
        try:
            subprocess.run(cmd, check=True, env=env, capture_output=True, text=True)
            print(f"Database restored from: {dump_file}")
        except FileNotFoundError:
            print("WARNING: psql not found — skipping database restore")
        except subprocess.CalledProcessError as e:
            print(f"WARNING: psql failed: {e.stderr}")
    else:
        print("WARNING: No database.sql found in backup")

    # Restore config
    config_src = backup_path / "config"
    config_dst = Path(os.environ.get("SHARED_CONFIG_DIR", "shared/config"))
    if config_src.is_dir():
        config_dst.mkdir(parents=True, exist_ok=True)
        shutil.copytree(config_src, config_dst, dirs_exist_ok=True)
        print(f"Config restored to: {config_dst}")

    # Restore reports
    reports_src = backup_path / "reports"
    reports_dst = Path(os.environ.get("SHARED_REPORTS_DIR", "shared/reports"))
    if reports_src.is_dir():
        reports_dst.mkdir(parents=True, exist_ok=True)
        shutil.copytree(reports_src, reports_dst, dirs_exist_ok=True)
        print(f"Reports restored to: {reports_dst}")

    print(f"\nRestore complete from: {backup_dir}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/restore.py <backup_dir>")
        sys.exit(1)
    restore(sys.argv[1])
