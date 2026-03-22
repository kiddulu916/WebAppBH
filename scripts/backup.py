#!/usr/bin/env python3
"""Backup WebAppBH database and config files.

Usage:
    python scripts/backup.py [output_dir]

Default output_dir is ./backups/
"""
import os
import subprocess
import shutil
import sys
from datetime import datetime
from pathlib import Path

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "webbh")
DB_USER = os.environ.get("DB_USER", "webbh_admin")
DB_PASS = os.environ.get("DB_PASS", "")


def backup(output_dir: str = "backups") -> str:
    """Create a timestamped backup of the database and config files."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = Path(output_dir) / f"webbh_backup_{ts}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    # pg_dump
    dump_file = backup_dir / "database.sql"
    cmd = [
        "pg_dump",
        "-h", DB_HOST,
        "-p", DB_PORT,
        "-U", DB_USER,
        "-d", DB_NAME,
        "-f", str(dump_file),
        "--no-owner",
        "--no-privileges",
    ]
    env = {**os.environ, "PGPASSWORD": DB_PASS}
    try:
        subprocess.run(cmd, check=True, env=env, capture_output=True, text=True)
        print(f"Database dumped to: {dump_file}")
    except FileNotFoundError:
        print("WARNING: pg_dump not found — skipping database backup")
    except subprocess.CalledProcessError as e:
        print(f"WARNING: pg_dump failed: {e.stderr}")

    # Copy shared config
    config_src = Path(os.environ.get("SHARED_CONFIG_DIR", "shared/config"))
    if config_src.is_dir():
        config_dst = backup_dir / "config"
        shutil.copytree(config_src, config_dst, dirs_exist_ok=True)
        print(f"Config copied to: {config_dst}")

    # Copy reports
    reports_src = Path(os.environ.get("SHARED_REPORTS_DIR", "shared/reports"))
    if reports_src.is_dir():
        reports_dst = backup_dir / "reports"
        shutil.copytree(reports_src, reports_dst, dirs_exist_ok=True)
        print(f"Reports copied to: {reports_dst}")

    print(f"\nBackup complete: {backup_dir}")
    return str(backup_dir)


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "backups"
    backup(output)
