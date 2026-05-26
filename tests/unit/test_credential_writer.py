import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest
from orchestrator.routes.campaigns import _write_credentials


def test_write_credentials_creates_file():
    with tempfile.TemporaryDirectory() as tmp:
        _write_credentials(
            42,
            tester={"username": "tester", "password": "pass", "auth_type": "form"},
            testing_user={"username": "victim", "email": "v@example.com", "password": "vpass"},
            base_dir=tmp,
        )
        creds_path = Path(tmp) / "42" / "credentials.json"
        assert creds_path.exists()
        data = json.loads(creds_path.read_text())
        assert data["tester"]["username"] == "tester"
        assert data["testing_user"]["password"] == "vpass"


@pytest.mark.skipif(sys.platform == "win32", reason="chmod 0o600 is a no-op on Windows")
def test_write_credentials_sets_permissions():
    with tempfile.TemporaryDirectory() as tmp:
        _write_credentials(
            99,
            tester={"username": "t", "password": "p", "auth_type": "basic"},
            testing_user=None,
            base_dir=tmp,
        )
        creds_path = Path(tmp) / "99" / "credentials.json"
        mode = stat.S_IMODE(os.stat(creds_path).st_mode)
        assert mode == 0o600


def test_write_credentials_skips_when_both_none():
    with tempfile.TemporaryDirectory() as tmp:
        _write_credentials(1, tester=None, testing_user=None, base_dir=tmp)
        assert not (Path(tmp) / "1").exists()
