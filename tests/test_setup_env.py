import os
import sys
import tempfile

# Add shared/ to path so we can import setup_env
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from setup_env import generate_env


def test_generate_env_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_path = os.path.join(tmpdir, ".env")
        generate_env(output_path=env_path)
        assert os.path.exists(env_path)


def test_generate_env_contains_required_keys():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_path = os.path.join(tmpdir, ".env")
        generate_env(output_path=env_path)
        with open(env_path) as f:
            content = f.read()
        assert "WEB_APP_BH_API_KEY=" in content
        assert "HOST_IP=" in content
        assert "DB_HOST=" in content
        assert "DB_PORT=" in content
        assert "DB_NAME=" in content
        assert "DB_USER=" in content
        assert "DB_PASS=" in content
        assert "REDIS_HOST=" in content
        assert "REDIS_PORT=" in content


def test_api_key_is_64_chars():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_path = os.path.join(tmpdir, ".env")
        generate_env(output_path=env_path)
        with open(env_path) as f:
            for line in f:
                if line.startswith("WEB_APP_BH_API_KEY="):
                    key = line.strip().split("=", 1)[1]
                    assert len(key) == 64
                    break


def test_idempotent_does_not_overwrite():
    with tempfile.TemporaryDirectory() as tmpdir:
        env_path = os.path.join(tmpdir, ".env")
        generate_env(output_path=env_path)
        with open(env_path) as f:
            first_content = f.read()
        generate_env(output_path=env_path)
        with open(env_path) as f:
            second_content = f.read()
        assert first_content == second_content
