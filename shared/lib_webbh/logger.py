"""Structured JSON logger with bind() context for lib_webbh.

Provides ``setup_logger`` which returns a ``BoundLogger`` that emits
JSON to both *stdout* and a rotating log file.  ``BoundLogger.bind()``
creates a child logger carrying extra context fields.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    """Formats every ``logging.LogRecord`` as a single-line JSON object.

    Output keys
    -----------
    timestamp : str   – UTC ISO-8601
    level     : str   – e.g. "INFO"
    logger    : str   – the *friendly* name passed to ``setup_logger``
    message   : str
    container : str   – from ``HOSTNAME`` env var (empty string if unset)
    target_id : Any   – pulled from bound context (``None`` if absent)
    extra     : dict  – everything else (``asset_type``, call-site extras)
    """

    def __init__(self, logger_name: str) -> None:
        super().__init__()
        self._logger_name = logger_name

    def format(self, record: logging.LogRecord) -> str:
        # Bound context injected via BoundLogger
        bound_ctx: Dict[str, Any] = getattr(record, "_bound_context", {})
        # Per-call extra dict
        call_extra: Dict[str, Any] = getattr(record, "_call_extra", {})

        # Build the extra dict: start with bound context extras, overlay
        # call-site extras so per-call values win.
        extra: Dict[str, Any] = {}
        for key, value in bound_ctx.items():
            if key == "target_id":
                continue  # target_id goes to the top level
            extra[key] = value
        extra.update(call_extra)

        # Top-level target_id from bound context (may be overridden by call)
        target_id = bound_ctx.get("target_id")

        payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": self._logger_name,
            "message": record.getMessage(),
            "container": os.environ.get("HOSTNAME", ""),
            "target_id": target_id,
            "extra": extra,
        }

        if record.exc_info and record.exc_info[1] is not None:
            payload["traceback"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Bound logger
# ---------------------------------------------------------------------------

class BoundLogger:
    """Thin wrapper around a stdlib logging.Logger that carries bound context.

    Intentionally does NOT inherit from logging.LoggerAdapter.
    A custom wrapper provides cleaner separation between bound context
    (target_id, asset_type) and per-call extras, which LoggerAdapter.process()
    conflates into a single extra dict on the LogRecord.

    Parameters
    ----------
    logger : logging.Logger
        The underlying stdlib logger (already has handlers attached).
    context : dict
        Persistent key/value pairs injected into every record.
    """

    def __init__(self, logger: logging.Logger, context: Optional[Dict[str, Any]] = None) -> None:
        self._logger = logger
        self._context: Dict[str, Any] = dict(context) if context else {}

    # -- public API ---------------------------------------------------------

    def bind(self, **kwargs: Any) -> "BoundLogger":
        """Return a *new* ``BoundLogger`` with merged context."""
        merged = {**self._context, **kwargs}
        return BoundLogger(self._logger, merged)

    # -- logging methods ----------------------------------------------------

    def debug(self, msg: str, *, extra: Optional[Dict[str, Any]] = None) -> None:
        self._log(logging.DEBUG, msg, extra)

    def info(self, msg: str, *, extra: Optional[Dict[str, Any]] = None) -> None:
        self._log(logging.INFO, msg, extra)

    def warning(self, msg: str, *, extra: Optional[Dict[str, Any]] = None) -> None:
        self._log(logging.WARNING, msg, extra)

    def error(self, msg: str, *, extra: Optional[Dict[str, Any]] = None) -> None:
        self._log(logging.ERROR, msg, extra)

    def critical(self, msg: str, *, extra: Optional[Dict[str, Any]] = None) -> None:
        self._log(logging.CRITICAL, msg, extra)

    def exception(self, msg: str, *, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log at ERROR level with current exception traceback attached."""
        self._log(logging.ERROR, msg, extra, exc_info=True)

    # -- internals ----------------------------------------------------------

    def _log(self, level: int, msg: str, call_extra: Optional[Dict[str, Any]], exc_info: Any = None) -> None:
        """Create a LogRecord, inject context, and hand it to the logger."""
        if not self._logger.isEnabledFor(level):
            return
        # Resolve exc_info=True to actual exception tuple (Logger._log does
        # this automatically, but we call makeRecord directly).
        if exc_info:
            if isinstance(exc_info, BaseException):
                exc_info = (type(exc_info), exc_info, exc_info.__traceback__)
            elif not isinstance(exc_info, tuple):
                exc_info = sys.exc_info()
        record = self._logger.makeRecord(
            name=self._logger.name,
            level=level,
            fn="",
            lno=0,
            msg=msg,
            args=(),
            exc_info=exc_info,
        )
        record._bound_context = self._context  # type: ignore[attr-defined]
        record._call_extra = call_extra or {}  # type: ignore[attr-defined]
        self._logger.handle(record)


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def setup_logger(name: str, log_dir: str = "/app/shared/logs/") -> BoundLogger:
    """Create (or retrieve) a named logger with JSON stdout + file output.

    Parameters
    ----------
    name : str
        Friendly identifier that appears in the ``logger`` JSON field and
        is used as the log-file stem (``<name>.log``).
    log_dir : str
        Directory for the rotating log file.  Created if it doesn't exist.

    Returns
    -------
    BoundLogger
        A logger instance supporting ``.bind()`` and standard level methods.
    """
    # Use a namespaced internal name to avoid clashes with third-party loggers
    internal_name = f"lib_webbh.{name}"
    logger = logging.getLogger(internal_name)

    # Avoid adding duplicate handlers on repeated calls with the same name
    if logger.handlers:
        return BoundLogger(logger)

    # Level from env
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))
    logger.propagate = False

    formatter = JsonFormatter(logger_name=name)

    # 1. StreamHandler -> stdout
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # 2. RotatingFileHandler -> <log_dir>/<name>.log
    #    Gracefully skip file logging if permissions deny access (e.g.
    #    Docker user-namespace remapping makes host files unwritable).
    try:
        os.makedirs(log_dir, exist_ok=True)
        file_path = os.path.join(log_dir, f"{name}.log")
        file_handler = RotatingFileHandler(
            file_path,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except PermissionError:
        # stdout handler is already attached; warn and continue
        logger.warning(f"Cannot write to {log_dir}{name}.log — file logging disabled")

    return BoundLogger(logger)
