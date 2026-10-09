"""Metadata that MDaemon-style log filenames carry: the day and the log type.

A log file is identified by a free prefix, a date and an optional suffix, for
example ``SMTP-In-2026-08-26.log`` or ``MDaemon-2026-08-26-System.log``. The
prefix in front of the date is what support calls the log type.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import PurePath

DATE_PATTERNS = (
    re.compile(r"(?<!\d)(?P<y>20\d{2})[-_.](?P<m>0[1-9]|1[0-2])[-_.](?P<d>0[1-9]|[12]\d|3[01])(?!\d)"),
    re.compile(r"(?<!\d)(?P<y>20\d{2})(?P<m>0[1-9]|1[0-2])(?P<d>0[1-9]|[12]\d|3[01])(?!\d)"),
)

UNSPECIFIED_TYPE = "Unspecified"
DEFAULT_EXTENSIONS = (".log", ".txt", ".xml", ".csv", ".json")


def date_from_name(name: str) -> date | None:
    """Return the first plausible date in a filename, or None."""
    leaf = PurePath(name.replace("\\", "/")).name
    for pattern in DATE_PATTERNS:
        for match in pattern.finditer(leaf):
            try:
                return date(int(match["y"]), int(match["m"]), int(match["d"]))
            except ValueError:
                continue
    return None


def log_type_from_name(name: str) -> str:
    """Return the filename part in front of the first recognized date."""
    stem = PurePath(name.replace("\\", "/")).stem
    cut = len(stem)
    for pattern in DATE_PATTERNS:
        match = pattern.search(stem)
        if match and match.start() < cut:
            cut = match.start()
    log_type = stem[:cut].strip("-_. ")
    return log_type or UNSPECIFIED_TYPE


def matches_log_type(log_type: str, patterns: list[str] | tuple[str, ...] | None) -> bool:
    """Case-insensitive match against literal names or fnmatch-style patterns."""
    if not patterns:
        return True
    from fnmatch import fnmatch

    lowered = log_type.lower()
    return any(fnmatch(lowered, pattern.lower()) for pattern in patterns)


def normalize_extensions(extensions: list[str] | tuple[str, ...] | None) -> set[str]:
    values = extensions if extensions else DEFAULT_EXTENSIONS
    normalized = set()
    for extension in values:
        if not extension:
            continue
        text = extension if extension.startswith(".") else "." + extension
        normalized.add(text.lower())
    if not normalized:
        raise ValueError("At least one file extension must be allowed.")
    return normalized
