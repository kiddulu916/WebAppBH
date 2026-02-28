import json
import logging
import os
import tempfile

from lib_webbh.logger import setup_logger


def test_setup_logger_returns_bound_logger():
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-worker", log_dir=tmpdir)
        assert log is not None
        assert hasattr(log, "bind")


def test_json_format_to_stdout(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-stdout", log_dir=tmpdir)
        log.info("hello world")
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["message"] == "hello world"
        assert record["level"] == "INFO"
        assert record["logger"] == "test-stdout"
        assert "timestamp" in record


def test_json_format_includes_extra(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-extra", log_dir=tmpdir)
        log.info("found asset", extra={"asset_type": "subdomain", "asset": "api.example.com"})
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["extra"]["asset_type"] == "subdomain"
        assert record["extra"]["asset"] == "api.example.com"


def test_bind_injects_context(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-bind", log_dir=tmpdir)
        bound = log.bind(target_id=42, asset_type="ipv4")
        bound.info("scanning")
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["target_id"] == 42
        assert record["extra"]["asset_type"] == "ipv4"


def test_log_writes_to_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-file", log_dir=tmpdir)
        log.info("file entry")
        log_path = os.path.join(tmpdir, "test-file.log")
        assert os.path.exists(log_path)
        with open(log_path) as f:
            record = json.loads(f.readline().strip())
        assert record["message"] == "file entry"


def test_bind_extra_override(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-override", log_dir=tmpdir)
        bound = log.bind(asset_type="domain")
        bound.info("override test", extra={"asset_type": "subdomain"})
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["extra"]["asset_type"] == "subdomain"


def test_log_level_from_env(monkeypatch, capsys):
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-level", log_dir=tmpdir)
        log.info("should be suppressed")
        log.warning("should appear")
        captured = capsys.readouterr()
        lines = [l for l in captured.out.strip().splitlines() if l]
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["level"] == "WARNING"


def test_container_from_hostname_env(monkeypatch, capsys):
    monkeypatch.setenv("HOSTNAME", "worker-abc123")
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-container", log_dir=tmpdir)
        log.info("check container")
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["container"] == "worker-abc123"


def test_timestamp_is_utc_iso8601(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-ts", log_dir=tmpdir)
        log.info("ts check")
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        ts = record["timestamp"]
        assert "+00:00" in ts or ts.endswith("Z")


def test_bind_does_not_mutate_parent(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        log = setup_logger("test-immutable", log_dir=tmpdir)
        parent = log.bind(target_id=1)
        child = parent.bind(target_id=2)
        parent.info("parent msg")
        captured = capsys.readouterr()
        record = json.loads(captured.out.strip())
        assert record["target_id"] == 1
