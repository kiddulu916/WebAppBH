"""Test backup/restore scripts (unit tests only, no actual pg_dump)."""
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from backup import backup
from restore import restore


def test_backup_creates_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("backup.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("pg_dump not found")
            result = backup(tmpdir)
            assert Path(result).is_dir()
            assert "webbh_backup_" in result


def test_backup_copies_config(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "test.json").write_text('{"test": true}')

    output_dir = tmp_path / "backups"
    with patch.dict(os.environ, {"SHARED_CONFIG_DIR": str(config_dir)}):
        with patch("backup.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("pg_dump not found")
            result = backup(str(output_dir))
            backup_config = Path(result) / "config" / "test.json"
            assert backup_config.exists()


def test_restore_missing_dir():
    with pytest.raises(SystemExit):
        restore("/nonexistent/path")


def test_restore_copies_config(tmp_path):
    # Create a fake backup
    backup_dir = tmp_path / "backup"
    config_dir = backup_dir / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "test.json").write_text('{"restored": true}')

    restore_config = tmp_path / "restored_config"
    with patch.dict(os.environ, {"SHARED_CONFIG_DIR": str(restore_config)}):
        with patch("restore.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("psql not found")
            restore(str(backup_dir))
            assert (restore_config / "test.json").exists()
