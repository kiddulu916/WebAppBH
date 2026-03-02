"""Module-level logger patch for test environments.
Import this BEFORE any orchestrator module."""
import atexit
import shutil
import tempfile
import lib_webbh
import lib_webbh.logger

_test_log_dir = tempfile.mkdtemp()
atexit.register(shutil.rmtree, _test_log_dir, ignore_errors=True)

_orig_setup_logger = lib_webbh.logger.setup_logger


def _patched_setup_logger(name, log_dir=_test_log_dir):
    return _orig_setup_logger(name, log_dir=log_dir)


lib_webbh.logger.setup_logger = _patched_setup_logger
lib_webbh.setup_logger = _patched_setup_logger
