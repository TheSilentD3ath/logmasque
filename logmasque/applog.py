"""Log file for the tool itself, so a failed run can be diagnosed afterwards.

The log records what the tool did - requests, jobs, store operations - never
log content. It does contain local file paths, so it is local diagnostic data
and should be looked at before it is passed on, like the collection manifest.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

LOGGER_NAME = "logmasque"
MAX_BYTES = 1_000_000
BACKUPS = 3


def default_log_path() -> Path:
    from .store import default_store_path

    return default_store_path().parent / "logmasque.log"


def setup(path: str | Path | None = None, debug: bool = False, console: bool = True) -> Path:
    """Attach handlers once and return the log file path."""
    target = Path(path) if path else default_log_path()
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.handlers.RotatingFileHandler(
        target, maxBytes=MAX_BYTES, backupCount=BACKUPS, encoding="utf-8"
    )
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(threadName)-18s %(message)s"))
    logger.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler()
        stream.setLevel(logging.WARNING)
        stream.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logger.addHandler(stream)
    return target


def get() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
