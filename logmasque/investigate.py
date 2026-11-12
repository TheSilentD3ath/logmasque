"""Log Investigator: a local index of log files to search, correlate and export.

An investigation is one SQLite file in the folder next to the mapping store.
Importing reads every file once, line by line, and never writes to it: the
lines, the events the format parser finds, the identifiers in them (entities)
and where each one occurs. Search, timeline and correlation then work on the
index, so nothing is parsed twice.

The original values stay visible here; this is the internal view. Only the
export for outside analysis runs the events through the anonymizer, with the
same mapping store and placeholders as everywhere else in LogMasque, and holds
back anything an original value would still be readable in.

Correlation knows three levels:

* direct   - an explicit shared identifier: the same event, session, request or
             processing block, or a shared Message-ID or queue file.
* strong   - a shared identity (address, account, device) close in time.
* possible - a shared identity far apart in time, a shared address (NAT, proxy)
             close in time, or (when asked for) closeness in time alone.

Values that occur in too many unrelated places - the server's own address, a
NAT address, the own domain, postmaster - are marked frequent or generic and
not used to link events unless the user says so.
"""

from __future__ import annotations

import bisect
import contextlib
import functools
import hashlib
import json
import multiprocessing
import multiprocessing.connection
import os
import re
import signal
import sqlite3
import struct
import time
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePath
from urllib.parse import urlsplit

from . import entities, logformats
from .anonymize import _OWN_OUTPUT, _SECRET_HINTS, Anonymizer, Options, find_leaks
from .entities import IP_KINDS, KIND_LABELS, LINK_KINDS, UNIQUE_KINDS, WEAK_KINDS
from .lognames import DATE_PATTERNS, DEFAULT_EXTENSIONS, date_from_name
from .mapping import Mapping

SUFFIX = ".lminv"
EPOCH = datetime(1970, 1, 1)
DIRECT, STRONG, POSSIBLE = 1, 2, 3
LEVEL_LABELS = {DIRECT: "direkt", STRONG: "stark", POSSIBLE: "möglich"}
# A Message-ID or queue file seen in this many separate contexts is reused, and
# a domain or host this widespread is noted as frequent.
COMMON_MIN_GROUPS = 40
# An address several accounts log in from is shared: a NAT router, a proxy or
# the server itself. It links nothing about one of them.
SHARED_IP_ACCOUNTS = 3
# A bracketed id that stays in use longer than this names a worker, not a request.
REQUEST_MAX_EVENTS = 400
REQUEST_MAX_MS = 30 * 60 * 1000
CONTEXT_KINDS = ("session", "request")
# Sort key of events without a time: after every real one, so one index serves
# the timeline order, time ranges and the first and last time.
SENTINEL = 1 << 62
# Events per bin of the stored time distribution: ten minutes.
BIN_MS = 10 * 60 * 1000
# Every so many lines the byte offset is kept, to read context from the file.
MARK_EVERY = 256
# Large files are committed in portions, so they can be searched while read.
COMMIT_EVERY = 50_000
STATS_VERSION = 2
# Hits are counted up to here; below it the time strip is exact, above it binned.
COUNT_CAP = 100_000
# Events per compressed text block, as a power of two: block = id >> TEXT_SHIFT.
# Blocks of 512 compress well, fill the pages of the index file and still
# unpack in a tenth of a millisecond.
TEXT_SHIFT = 9
TEXT_BLOCK = 1 << TEXT_SHIFT
# The text of the event e, wherever it is kept.
TEXT_SQL = f"COALESCE(e.message, event_text(e.id, (SELECT t.data FROM texts t WHERE t.block = e.id >> {TEXT_SHIFT})))"
# All columns of the event e, with its text as message.
EVENT_COLUMNS = (
    "e.id, e.source_id, e.line_start, e.line_end, e.wall_ms, e.line_off, e.raw_flag, e.off_min, e.ts_ms, e.ts_flag, "
    f"e.etype, e.severity, e.ctx, e.sort_ms, {TEXT_SQL} AS message"
)
SENSITIVE_KINDS = frozenset({"email", "account", "device", "ipv4", "ipv6", "endpoint", "domain", "host", "url", "msgid"})

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sources(
    id INTEGER PRIMARY KEY, path TEXT, name TEXT, sha256 TEXT UNIQUE, size INTEGER, parser TEXT,
    parser_label TEXT, encoding TEXT, lines INTEGER DEFAULT 0, events INTEGER DEFAULT 0,
    first_ms INTEGER, last_ms INTEGER, detected_offset INTEGER, tz_mode TEXT DEFAULT 'auto',
    tz_offset INTEGER, skew_ms INTEGER DEFAULT 0, imported_at TEXT,
    mtime_ns INTEGER, state TEXT DEFAULT 'ready', stated TEXT, etypes TEXT, time_flags TEXT, head TEXT
);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY, source_id INTEGER, line_start INTEGER, line_end INTEGER,
    wall_ms INTEGER, line_off INTEGER, raw_flag TEXT, off_min INTEGER, ts_ms INTEGER, ts_flag TEXT,
    etype TEXT, severity INTEGER, ctx INTEGER, message TEXT, sort_ms INTEGER
);
-- The session, request or processing block an event belongs to, by number;
-- the key names it, "5:session:1:00000002" for session 2 after the first restart.
CREATE TABLE IF NOT EXISTS contexts(id INTEGER PRIMARY KEY, key TEXT UNIQUE);
-- Most events belong to no session or request; they need no entry here.
CREATE INDEX IF NOT EXISTS events_ctx ON events(ctx) WHERE ctx IS NOT NULL;
-- The text of the events, compressed in blocks of TEXT_BLOCK consecutive
-- events: log lines repeat so much that a block takes an eighth to a fifth
-- of the space.
-- Events of the first versions keep their text in events.message instead.
CREATE TABLE IF NOT EXISTS texts(block INTEGER PRIMARY KEY, data BLOB);
CREATE INDEX IF NOT EXISTS events_source ON events(source_id, line_start);
CREATE TABLE IF NOT EXISTS entities(
    id INTEGER PRIMARY KEY, kind TEXT, value TEXT, display TEXT, events INTEGER DEFAULT 0,
    groups INTEGER DEFAULT 0, sources INTEGER DEFAULT 0, first_ms INTEGER, last_ms INTEGER,
    common INTEGER DEFAULT 0, generic INTEGER DEFAULT 0, UNIQUE(kind, value)
);
CREATE INDEX IF NOT EXISTS entities_value ON entities(value);
CREATE TABLE IF NOT EXISTS occurrences(
    entity_id INTEGER, event_id INTEGER, role TEXT DEFAULT '', PRIMARY KEY(entity_id, event_id, role)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS occurrences_event ON occurrences(event_id);
CREATE TABLE IF NOT EXISTS excluded(entity_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS included(entity_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS link_excluded(a INTEGER, b INTEGER, PRIMARY KEY(a, b));
CREATE TABLE IF NOT EXISTS marks(
    source_id INTEGER, lineno INTEGER, offset INTEGER, PRIMARY KEY(source_id, lineno)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bins(
    source_id INTEGER, bin INTEGER, severity INTEGER, n INTEGER, PRIMARY KEY(source_id, bin, severity)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS entity_source(
    entity_id INTEGER, source_id INTEGER, events INTEGER, groups INTEGER, first_ms INTEGER, last_ms INTEGER,
    PRIMARY KEY(entity_id, source_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS entity_source_source ON entity_source(source_id);
CREATE TABLE IF NOT EXISTS ip_accounts(
    ip_id INTEGER, account_id INTEGER, source_id INTEGER, PRIMARY KEY(ip_id, account_id, source_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ip_accounts_source ON ip_accounts(source_id);
"""
# Columns added after the first release, for investigations made before.
ADDED_COLUMNS = {
    "sources": ("mtime_ns INTEGER", "state TEXT DEFAULT 'ready'", "stated TEXT", "etypes TEXT", "time_flags TEXT", "head TEXT"),
    "events": ("sort_ms INTEGER",),
}


class InvestigationError(ValueError):
    """Shown to the user as is."""


class ImportCancelled(InvestigationError):
    """The user stopped an import; files read completely so far stay."""


# -- time ------------------------------------------------------------------------


def to_ms(value: datetime) -> int:
    delta = value - EPOCH
    return delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000


def format_ms(value: int | None, offset_min: int | None = None) -> str:
    if value is None:
        return ""
    zone = timezone(timedelta(minutes=offset_min or 0))
    stamp = datetime.fromtimestamp(value / 1000, zone)
    return stamp.strftime("%Y-%m-%d %H:%M:%S.") + f"{value % 1000:03d}"


_local_cache: dict[int, int] = {}


def local_offset(wall_ms: int) -> int:
    """Minutes east of UTC on this computer at that wall-clock time, summer time included."""
    hour = wall_ms // 3_600_000
    cached = _local_cache.get(hour)
    if cached is None:
        try:
            moment = EPOCH + timedelta(milliseconds=wall_ms)
            cached = round((wall_ms / 1000 - time.mktime(moment.timetuple())) / 60)
        except (OverflowError, ValueError):
            cached = 0
        _local_cache[hour] = cached
    return cached


TIME_FLAG_LABELS = {
    "exact": "Zeitzone steht in der Zeile",
    "source": "Zeitzone der Quelle",
    "inferred": "Zeitzone aus anderen Quellen dieser Untersuchung übernommen",
    "local": "Zeitzone dieses Rechners angenommen",
    "inherited": "keine eigene Zeit, von der Zeile davor übernommen",
    "ambiguous": "Zeitangabe mehrdeutig",
    "invalid": "Zeitstempel ungültig",
    "none": "ohne Zeitangabe",
}


# -- investigations on disk ----------------------------------------------------


def investigations_folder(store_path: str | Path) -> Path:
    return Path(store_path).parent / "investigations"


def list_investigations(folder: Path) -> list[dict]:
    result = []
    for path in sorted(folder.glob(f"*{SUFFIX}")) if folder.is_dir() else []:
        try:
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
                meta = dict(db.execute("SELECT key, value FROM meta").fetchall())
                sources = db.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        except sqlite3.Error:
            continue
        result.append({
            "id": path.stem, "name": meta.get("name", path.stem), "created": meta.get("created", ""),
            "sources": sources, "size": path.stat().st_size,
        })
    return result


def create_investigation(folder: Path, name: str) -> "Investigation":
    name = name.strip() or "Untersuchung"
    folder.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-")[:40] or "untersuchung"
    path = folder / f"{slug}-{uuid.uuid4().hex[:8]}{SUFFIX}"
    investigation = Investigation(path)
    with investigation.connect() as db:
        db.execute("INSERT OR REPLACE INTO meta VALUES ('name', ?)", (name,))
        db.execute("INSERT OR REPLACE INTO meta VALUES ('created', ?)", (datetime.now().strftime("%Y-%m-%d %H:%M"),))
    return investigation


def investigation_path(folder: Path, investigation_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", investigation_id or ""):
        raise InvestigationError("Unbekannte Untersuchung.")
    path = folder / f"{investigation_id}{SUFFIX}"
    if not path.is_file():
        raise InvestigationError("Diese Untersuchung gibt es nicht mehr.")
    return path


def delete_investigation(folder: Path, investigation_id: str) -> None:
    path = investigation_path(folder, investigation_id)
    for suffix in ("", "-wal", "-shm"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def _fts_available() -> bool:
    try:
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE VIRTUAL TABLE probe USING fts5(text)")
        return True
    except sqlite3.Error:
        return False


FTS = _fts_available()


class Investigation:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._trace_cache: dict[tuple, dict] = {}
        self._version = 0
        with self.connect() as db:
            db.executescript(SCHEMA)
            self._upgrade(db)
            self._fts_positions = True
            if FTS:
                # Without token positions the text index takes a third of the
                # space; words of several tokens are then checked as text. It
                # keeps no copy of the text: entries are removed with the text
                # given (investigations of the first versions refer to events).
                try:
                    db.execute(
                        "CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(message, content='', "
                        "detail=none, columnsize=0)"
                    )
                except sqlite3.OperationalError:
                    db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(message, content='')")
                definition = db.execute("SELECT sql FROM sqlite_master WHERE name = 'events_fts'").fetchone()[0]
                self._fts_positions = "detail=none" not in definition.replace(" ", "").lower()

    def _upgrade(self, db) -> None:
        """Bring an investigation of an earlier version to the current layout; new ones pass through."""
        fresh = db.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 0
        for table, columns in ADDED_COLUMNS.items():
            present = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            for column in columns:
                if column.split()[0] not in present:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {column}")
                    if column.startswith("sort_ms"):
                        db.execute("UPDATE events SET sort_ms = COALESCE(ts_ms, ?)", (SENTINEL,))
        db.execute("CREATE INDEX IF NOT EXISTS events_sort ON events(sort_ms, source_id, line_start)")
        db.execute("DROP INDEX IF EXISTS events_ts")
        sample = db.execute("SELECT ctx FROM events WHERE ctx IS NOT NULL LIMIT 1").fetchone()
        if sample is not None and ":" in str(sample[0]):
            # The first version kept the key itself on every event.
            db.execute("INSERT OR IGNORE INTO contexts(key) SELECT DISTINCT ctx FROM events WHERE ctx IS NOT NULL")
            db.execute("UPDATE events SET ctx = (SELECT id FROM contexts WHERE key = events.ctx) WHERE ctx IS NOT NULL")
        if fresh:
            db.execute("INSERT OR IGNORE INTO meta VALUES ('stats_version', ?)", (str(STATS_VERSION),))

    @property
    def id(self) -> str:
        return self.path.stem

    @contextlib.contextmanager
    def connect(self):
        """A connection that commits on success, rolls back on error and is always closed."""
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            db.create_function("event_text", 2, _event_text, deterministic=True)
        except sqlite3.NotSupportedError:
            db.create_function("event_text", 2, _event_text)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            # The log of a long import shrinks back after each checkpoint.
            db.execute("PRAGMA journal_size_limit=67108864")
            # Occurrences go into the index in the order of their values, not of
            # the file: with the default cache of 2 MB, nearly every one is a read.
            db.execute("PRAGMA cache_size=-65536")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def meta(self, db, key: str, default: str = "") -> str:
        row = db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    # -- scan ------------------------------------------------------------------

    def scan_paths(self, paths: list[str], progress=None, cancelled=None) -> dict:
        """What would be imported, read from the head and tail of each file only.

        Size, log type, format, encoding and the first and last time stamp of
        every file, so the relevant part of a large collection can be chosen
        before anything is indexed.
        """
        files = _expand(paths)
        if not files:
            raise InvestigationError("Keine Logdateien gefunden.")
        with self.connect() as db:
            known = {
                (row[0], row[1], row[2]) for row in db.execute("SELECT path, size, mtime_ns FROM sources")
            }
        items = []
        for index, path in enumerate(files):
            if cancelled is not None and cancelled():
                break
            try:
                item = peek_file(path)
            except OSError as error:
                item = {"path": str(path), "name": path.name, "size": 0, "kind": source_kind(path.name), "error": str(error)}
            item["imported"] = (item["path"], item.get("size"), item.get("mtimeNs")) in known
            items.append(item)
            if progress is not None:
                progress((index + 1) / len(files), path.name)
        # Earlier copies of growing logs, from samples of both files; the import checks them in full.
        copies = []
        for item in items:
            key = item.pop("key", None)
            if key is not None and not item["imported"] and not item.get("error"):
                copies.append(_Copy(item["name"], item["size"], key, Path(item["path"]), owner=item))
        if copies:
            with self.connect() as db:
                within = _continued(copies + _known_copies(db, copies), verify=False)
            for shorter, longer in within.items():
                end = _longest(within, longer)
                if shorter.owner is not None:
                    shorter.owner["within"] = _label(end, shorter)
                elif end.owner is not None:
                    end.owner.setdefault("replaces", []).append(_label(shorter, end))
        groups: dict[str, dict] = {}
        for item in items:
            group = groups.setdefault(item["kind"], {
                "kind": item["kind"], "files": 0, "size": 0, "imported": 0, "within": 0, "firstMs": None,
                "lastMs": None, "formats": set(),
            })
            group["files"] += 1
            group["size"] += item.get("size") or 0
            group["imported"] += 1 if item["imported"] else 0
            group["within"] += 1 if item.get("within") else 0
            if item.get("formatLabel"):
                group["formats"].add(item["formatLabel"])
            for key, pick in (("firstMs", min), ("lastMs", max)):
                if item.get(key) is not None:
                    group[key] = item[key] if group[key] is None else pick(group[key], item[key])
        for group in groups.values():
            group["formats"] = sorted(group["formats"])
        return {
            "files": items,
            "groups": sorted(groups.values(), key=lambda group: group["kind"].casefold()),
            "size": sum(item.get("size") or 0 for item in items),
            "complete": len(items) == len(files),
        }

    # -- import ----------------------------------------------------------------

    def import_paths(self, paths: list[str], progress=None, cancelled=None) -> dict:
        """Read files and folders into the index; the originals are opened read-only."""
        return self.import_plan(paths, (), progress=progress, cancelled=cancelled)

    def import_plan(
        self, priority: list[str], background=(), progress=None, cancelled=None, status=None, ready=None
    ) -> dict:
        """Import the priority files, report them ready, then the background files.

        Every file is usable as soon as it is read: its events are committed in
        portions, its times, statistics and the entity counts are brought up to
        date when it ends. So the investigation can be searched while the
        background files are still coming in.

        Large imports are read and parsed in helper processes, several files at
        a time, while this process writes what they found; the index is the
        same as when this process reads every file itself.
        """
        first = _expand(priority) if priority else []
        chosen = set(first)
        later = [path for path in (_expand(background) if background else []) if path not in chosen]
        if not first and not later:
            raise InvestigationError("Keine Logdateien gefunden.")
        jobs = [_Job(path, "priority") for path in first] + [_Job(path, "background") for path in later]
        files = len(jobs)
        total = sum(job.size for job in jobs) or 1
        report: dict = {"imported": [], "duplicates": [], "continued": [], "replaced": [], "failed": []}
        done = {"bytes": 0, "files": 0, "priority": len(first), "priorityFiles": len(first)}
        started = time.monotonic()

        def tell(name: str, read: int = 0, phase: str = "") -> None:
            phase = phase or ("priority" if done["priority"] else "background")
            if progress is not None:
                progress(min((done["bytes"] + read) / total, 0.99), name)
            if status is not None:
                status({
                    "phase": phase, "current": name, "files": done["files"], "filesTotal": files,
                    "priorityFiles": done["priorityFiles"], "bytes": done["bytes"] + read, "bytesTotal": total,
                    "elapsed": round(time.monotonic() - started, 1),
                })

        def finished(job: _Job, outcome=None, error: str = "", within: str = "") -> None:
            if error:
                report["failed"].append({"path": str(job.path), "error": error})
            elif within:
                report["continued"].append({"path": str(job.path), "within": within})
            elif outcome == "duplicate":
                report["duplicates"].append(str(job.path))
            elif outcome:
                report["imported"].append(outcome)
                report["replaced"].extend({"name": name, "by": outcome["name"]} for name in outcome.get("replaced", ()))
            done["bytes"] += job.size
            done["files"] += 1
            if job.phase == "priority":
                done["priority"] -= 1
                if not done["priority"] and ready is not None:
                    ready()

        def promote(job: _Job) -> None:
            """The longer copy of a priority file is read with the priority files."""
            job.phase = "priority"
            done["priority"] += 1
            done["priorityFiles"] += 1

        with self.connect() as db:
            self._ensure_stats(db, lambda name: tell(name, phase="prepare"))
            cache = _EntityCache(db)
            writer = _Writer(db, cache, self._changed)
            try:
                jobs = self._without_duplicates(db, jobs, finished, lambda name: tell(name, phase="prepare"), cancelled)
                jobs = self._without_earlier_copies(db, jobs, finished, promote, lambda name: tell(name, phase="prepare"))
                readers = _reader_count(sum(job.size for job in jobs), len(jobs))
                if readers:
                    jobs = self._import_parallel(db, jobs, readers, writer, finished, tell, cancelled, report)
                for job in jobs:
                    if cancelled is not None and cancelled():
                        raise ImportCancelled("Import abgebrochen.")
                    tell(job.path.name)
                    try:
                        outcome = self._import_file(
                            db, job, lambda read, name=job.path.name: tell(name, read), cancelled, writer
                        )
                    except (OSError, UnicodeError, sqlite3.Error) as error:
                        finished(job, error=str(error))
                    else:
                        finished(job, outcome)
            except ImportCancelled:
                report["cancelled"] = True
            elapsed = time.monotonic() - started
            if report["imported"] and done["bytes"] > 20 * 1024 * 1024 and elapsed > 10:
                # Measured on this machine, for the estimates of the next import.
                db.execute("INSERT OR REPLACE INTO meta VALUES ('rate', ?)", (str(round(done["bytes"] / elapsed)),))
            db.commit()
            _checkpoint(db)
        tell("", phase="done")
        return report

    def _without_duplicates(self, db, jobs: list["_Job"], finished, tell, cancelled) -> list["_Job"]:
        """The files not imported before, the first of equal files of this import.

        Only a file of the size of another needs its checksum in advance; the
        others get it while they are read. Checksums run at the speed of the
        disk, far ahead of reading the events, and keep the choice of which
        copy stays independent of which one is read first.
        """
        sizes = {row[0] for row in db.execute("SELECT DISTINCT size FROM sources")}
        counts: dict[int, int] = {}
        for job in jobs:
            counts[job.size] = counts.get(job.size, 0) + 1
        known = {row[0] for row in db.execute("SELECT sha256 FROM sources WHERE sha256 IS NOT NULL")}
        remaining = []
        for job in jobs:
            if job.size in sizes or counts[job.size] > 1:
                if cancelled is not None and cancelled():
                    raise ImportCancelled("Import abgebrochen.")
                tell(job.path.name)
                try:
                    job.digest = _sha256(job.path)
                except OSError as error:
                    finished(job, error=str(error))
                    continue
                if job.digest in known:
                    finished(job, "duplicate")
                    continue
                known.add(job.digest)
            remaining.append(job)
        return remaining

    def _without_earlier_copies(self, db, jobs: list["_Job"], finished, promote, tell) -> list["_Job"]:
        """Of the copies of a growing log, only the longest is read; it replaces shorter ones in the index.

        A file to import that a longer one begins with, to import or imported,
        is left out. An imported file that a file to import begins with is
        removed once that file is in, with its zone and clock settings handed on.
        """
        copies = [
            _Copy(job.path.name, job.size, _start_key(job.path), job.path, job.digest, owner=job)
            for job in jobs if job.size >= KEY_BYTES
        ]
        if not copies:
            return jobs
        tell("Fortgeschriebene Logdateien prüfen")
        within = _continued(copies + _known_copies(db, copies), verify=True)
        left_out = {}
        for shorter, longer in within.items():
            end = _longest(within, longer)
            if shorter.owner is not None:
                left_out[shorter.owner] = _label(end, shorter)
                if end.owner is not None and shorter.owner.phase == "priority" and end.owner.phase != "priority":
                    promote(end.owner)
            elif end.owner is not None:
                end.owner.replaces.append(shorter.source)
        for job, name in left_out.items():
            finished(job, within=name)
        remaining = [job for job in jobs if job not in left_out]
        remaining.sort(key=lambda job: job.phase != "priority")
        return remaining

    def _replace_source(self, db, writer: "_Writer", old: int, new: int) -> str:
        """An earlier copy goes once the longer one is in; its zone and clock settings stay."""
        row = db.execute("SELECT name, tz_mode, tz_offset, skew_ms FROM sources WHERE id = ?", (old,)).fetchone()
        if row is None:
            return ""
        before = self._naive_offset(db)
        self._drop_source(db, old)
        writer.cache.forget_pending()
        own = (row["tz_mode"] or "auto") != "auto" or bool(row["skew_ms"])
        if own:
            db.execute(
                "UPDATE sources SET tz_mode = ?, tz_offset = ?, skew_ms = ? WHERE id = ?",
                (row["tz_mode"], row["tz_offset"], row["skew_ms"], new),
            )
        if self._naive_offset(db) != before:
            self._retime(db)
            self._entity_stats(db, None)
        elif own:
            self._retime(db, [new])
            self._entity_stats(db, [new])
        return row["name"]

    def _import_file(self, db, job: "_Job", step, cancelled, writer: "_Writer") -> dict:
        encoding, fmt = _open_format(job.path)
        reading = self._start_source(db, job, encoding, fmt.name, fmt.label)
        try:
            info: dict = {}
            for record in _event_records(job.path, encoding, fmt, info, step, cancelled, job.digest is None):
                writer.add(reading, record)
            step(job.size)
            return self._end_source(db, writer, reading, info)
        except BaseException:
            # Portions of the file may be committed already; none of it stays.
            self._drop_sources(db, writer, [reading.source_id])
            raise

    def _start_source(self, db, job: "_Job", encoding: str, parser: str, label: str) -> "_Reading":
        stat = job.path.stat()
        reading = _Reading()
        reading.name = job.path.name
        reading.source_id = db.execute(
            "INSERT INTO sources(path, name, sha256, size, mtime_ns, parser, parser_label, encoding, imported_at, state, "
            "head) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'importing', ?)",
            (str(job.path), job.path.name, job.digest, stat.st_size, stat.st_mtime_ns, parser, label, encoding,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"), _start_key(job.path)),
        ).lastrowid
        reading.path = str(job.path)
        reading.replaces = list(job.replaces)
        reading.parser_label = label
        reading.default = self._naive_offset(db)
        db.commit()
        return reading

    def _end_source(self, db, writer: "_Writer", reading: "_Reading", info: dict) -> dict:
        writer.flush()
        reading.lines = info["lines"]
        reading.detected = info["detected"]
        reading.digest = info["digest"]
        if info["marks"]:
            db.executemany(
                "INSERT OR REPLACE INTO marks VALUES (?, ?, ?)",
                [(reading.source_id, number, offset) for number, offset in info["marks"]],
            )
        self._finish_source(db, reading.source_id, reading)
        replaced = [self._replace_source(db, writer, source_id, reading.source_id) for source_id in reading.replaces]
        writer.commit()
        outcome = {"path": reading.path, "name": reading.name, "parser": reading.parser_label, "lines": reading.lines}
        if any(replaced):
            outcome["replaced"] = [name for name in replaced if name]
        return outcome

    def _drop_sources(self, db, writer: "_Writer", source_ids: list[int]) -> None:
        """After a failure: the files being read go, with what was committed of them already."""
        writer.discard()
        db.rollback()
        writer.cache.forget_pending()
        for source_id in source_ids:
            self._drop_source(db, source_id)
        db.commit()

    def _import_parallel(
        self, db, jobs: list["_Job"], count: int, writer: "_Writer", finished, tell, cancelled, report: dict
    ) -> list["_Job"]:
        """Read and parse the files in helper processes, write their events here as they come in.

        Each helper takes the next file when it is through with one, the
        priority files first; the events of several files arrive interleaved,
        those of one file in the order of its lines. Returns the files to read
        here after all: none, or those left when the helpers fail.
        """
        try:
            pool = _Readers([(index, str(job.path), job.digest is None) for index, job in enumerate(jobs)], count)
        except (OSError, ValueError, ImportError, RuntimeError) as error:
            report["readers"] = {"count": 0, "fallback": str(error)}
            return jobs
        report["readers"] = {"count": count}
        active: dict[int, _Reading] = {}
        read: dict[int, int] = {}
        left = set(range(len(jobs)))
        told = 0.0
        try:
            while left:
                if cancelled is not None and cancelled():
                    raise ImportCancelled("Import abgebrochen.")
                message = pool.next()
                if message is None:
                    if pool.lost():
                        raise _ReadersLost("Ein Hilfsprozess des Imports ist ausgefallen.")
                    continue
                kind, index = message[0], message[1]
                job = jobs[index]
                if kind == "start":
                    try:
                        active[index] = self._start_source(db, job, message[2], message[3], message[4])
                    except OSError as error:
                        left.discard(index)
                        finished(job, error=str(error))
                elif kind == "error":
                    reading = active.pop(index, None)
                    read.pop(index, None)
                    if reading is not None:
                        writer.flush()
                        self._drop_source(db, reading.source_id)
                        writer.commit()
                        # Entities of that file alone are gone, and so are their numbers.
                        writer.cache.forget_pending()
                    if index in left:
                        left.discard(index)
                        finished(job, error=message[2])
                elif index not in active:
                    pass  # a file given up already
                elif kind == "events":
                    reading = active[index]
                    for record in message[2]:
                        writer.add(reading, record)
                    read[index] = message[3]
                elif kind == "done":
                    reading = active.pop(index)
                    read.pop(index, None)
                    left.discard(index)
                    finished(job, self._end_source(db, writer, reading, message[2]))
                now = time.monotonic()
                if now - told > 0.5:
                    told = now
                    names = [jobs[index].path.name for index in sorted(active)]
                    label = names[0] + (f" (+{len(names) - 1})" if len(names) > 1 else "") if names else ""
                    tell(label, sum(read.values()))
        except _ReadersLost as error:
            # What the helpers had not finished is read here instead.
            report["readers"]["fallback"] = str(error)
            self._drop_sources(db, writer, [reading.source_id for reading in active.values()])
            return [jobs[index] for index in sorted(left)]
        except sqlite3.Error as error:
            self._drop_sources(db, writer, [reading.source_id for reading in active.values()])
            for index in sorted(active):
                left.discard(index)
                finished(jobs[index], error=str(error))
            return [jobs[index] for index in sorted(left)]
        except BaseException:
            self._drop_sources(db, writer, [reading.source_id for reading in active.values()])
            raise
        finally:
            pool.close()
        return []

    @staticmethod
    def _flush(db, cache: "_EntityCache", event_rows: list, occurrence_rows: list, text_rows: list) -> None:
        cache.flush()
        if event_rows:
            db.executemany(
                "INSERT INTO events(id, source_id, line_start, line_end, wall_ms, line_off, raw_flag, off_min, ts_ms, "
                "ts_flag, etype, severity, ctx, sort_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                event_rows,
            )
            _store_texts(db, text_rows)
            # With its events, so every committed event can be found by its text.
            if FTS:
                db.executemany("INSERT INTO events_fts(rowid, message) VALUES (?, ?)", text_rows)
            event_rows.clear()
            text_rows.clear()
        if occurrence_rows:
            occurrence_rows.sort()
            db.executemany("INSERT OR IGNORE INTO occurrences VALUES (?, ?, ?)", occurrence_rows)
            occurrence_rows.clear()

    def _finish_source(self, db, source_id: int, reading: "_Reading") -> None:
        """Index the text, settle the times and bring statistics and entity counts up to date."""
        self._limit_request_contexts(db, source_id)
        before = self._naive_offset(db)
        db.execute(
            "UPDATE sources SET lines = ?, events = ?, detected_offset = ?, stated = ?, etypes = ?, "
            "sha256 = COALESCE(sha256, ?) WHERE id = ?",
            (reading.lines, reading.events, reading.detected, dumps(sorted(reading.stated)), dumps(reading.etypes),
             reading.digest, source_id),
        )
        default = self._naive_offset(db)
        if default != before:
            # This file states a zone the others did not: every file without a
            # zone of its own follows the new default.
            self._retime(db)
            self._entity_stats(db, None)
        else:
            # The zone its lines were given while reading may have changed since,
            # by a file that ended in the meantime.
            final = ("source", reading.detected) if reading.detected is not None else (
                (default[1], default[0]) if default[0] is not None else ("local", None)
            )
            if reading.bases - {final}:
                self._retime(db, [source_id])
            else:
                self._store_source_stats(db, source_id, reading)
            self._entity_stats(db, [source_id])
        db.execute("UPDATE sources SET state = 'ready' WHERE id = ?", (source_id,))

    @staticmethod
    def _limit_request_contexts(db, source_id: int) -> None:
        """A bracketed id that lives for hundreds of lines or half an hour is a worker thread."""
        long_lived = db.execute(
            "SELECT e.ctx, c.key FROM events e JOIN contexts c ON c.id = e.ctx WHERE e.source_id = ? "
            "AND c.key NOT LIKE ? GROUP BY e.ctx HAVING COUNT(*) > ? OR MAX(e.wall_ms) - MIN(e.wall_ms) > ?",
            (source_id, f"{source_id}:session:%", REQUEST_MAX_EVENTS, REQUEST_MAX_MS),
        ).fetchall()
        for context_id, key in long_lived:
            db.execute("UPDATE events SET ctx = NULL WHERE source_id = ? AND ctx = ?", (source_id, context_id))
            db.execute("DELETE FROM contexts WHERE id = ?", (context_id,))
            row = db.execute("SELECT id FROM entities WHERE kind = 'request' AND value = ?", (key,)).fetchone()
            if row:
                db.execute("DELETE FROM occurrences WHERE entity_id = ?", (row[0],))
                db.execute("DELETE FROM entities WHERE id = ?", (row[0],))

    def _changed(self) -> None:
        """New data is visible: traces computed before no longer hold."""
        self._version += 1
        self._trace_cache.clear()

    # -- statistics ----------------------------------------------------------------

    @staticmethod
    def _store_source_stats(db, source_id: int, reading: "_Reading") -> None:
        db.execute("DELETE FROM bins WHERE source_id = ?", (source_id,))
        db.executemany(
            "INSERT INTO bins VALUES (?, ?, ?, ?)",
            [(source_id, bin_, severity, count) for (bin_, severity), count in reading.bins.items()],
        )
        db.execute(
            "UPDATE sources SET time_flags = ?, first_ms = ?, last_ms = ? WHERE id = ?",
            (dumps(reading.flags), reading.first_ms, reading.last_ms, source_id),
        )

    @staticmethod
    def _source_stats(db, source_id: int) -> None:
        """Time flags, time bins and range of one file, from its events."""
        flags = dict(db.execute(
            "SELECT ts_flag, COUNT(*) FROM events WHERE source_id = ? GROUP BY ts_flag", (source_id,)
        ).fetchall())
        db.execute("DELETE FROM bins WHERE source_id = ?", (source_id,))
        db.execute(
            "INSERT INTO bins SELECT source_id, ts_ms / ?, severity, COUNT(*) FROM events "
            "WHERE source_id = ? AND ts_ms IS NOT NULL GROUP BY 2, 3", (BIN_MS, source_id),
        )
        span = db.execute("SELECT MIN(ts_ms), MAX(ts_ms) FROM events WHERE source_id = ?", (source_id,)).fetchone()
        db.execute(
            "UPDATE sources SET time_flags = ?, first_ms = ?, last_ms = ? WHERE id = ?",
            (dumps(flags), span[0], span[1], source_id),
        )

    def _entity_stats(self, db, source_ids: list[int] | None) -> None:
        """Counts per entity and file, the totals of the entities concerned, and the frequency marks.

        Counts are kept per file, so a new or removed file only touches the
        entities that occur in it; contexts never span files, so the totals
        are plain sums.
        """
        if source_ids is None:
            source_ids = [row[0] for row in db.execute("SELECT id FROM sources")]
            db.execute("DELETE FROM entity_source")
            db.execute("DELETE FROM ip_accounts")
        db.execute("CREATE TEMP TABLE IF NOT EXISTS touched(id INTEGER PRIMARY KEY)")
        db.execute("DELETE FROM temp.touched")
        for source_id in source_ids:
            db.execute("INSERT OR IGNORE INTO temp.touched SELECT entity_id FROM entity_source WHERE source_id = ?", (source_id,))
            db.execute("DELETE FROM entity_source WHERE source_id = ?", (source_id,))
            db.execute(
                "INSERT INTO entity_source SELECT o.entity_id, ?, COUNT(DISTINCT o.event_id), "
                "COUNT(DISTINCT COALESCE(e.ctx, -e.id)), MIN(e.ts_ms), MAX(e.ts_ms) "
                "FROM events e JOIN occurrences o ON o.event_id = e.id WHERE e.source_id = ? GROUP BY o.entity_id",
                (source_id, source_id),
            )
            db.execute("INSERT OR IGNORE INTO temp.touched SELECT entity_id FROM entity_source WHERE source_id = ?", (source_id,))
            # Accounts that log in from an address in the same session or request.
            db.execute("DELETE FROM ip_accounts WHERE source_id = ?", (source_id,))
            db.execute("DROP TABLE IF EXISTS temp.entity_group")
            db.execute(
                "CREATE TEMP TABLE entity_group AS SELECT DISTINCT o.entity_id AS entity_id, "
                "COALESCE(e.ctx, -e.id) AS grp, "
                "CASE WHEN n.kind = 'account' OR o.role = 'account' THEN 1 ELSE 0 END AS account "
                "FROM events e JOIN occurrences o ON o.event_id = e.id JOIN entities n ON n.id = o.entity_id "
                "WHERE e.source_id = ? AND (n.kind IN ('ipv4', 'ipv6', 'endpoint', 'account') OR o.role = 'account')",
                (source_id,),
            )
            db.execute("CREATE INDEX temp.entity_group_grp ON entity_group(grp)")
            db.execute(
                "INSERT OR IGNORE INTO ip_accounts SELECT DISTINCT a.entity_id, b.entity_id, ? FROM temp.entity_group a "
                "JOIN temp.entity_group b ON b.grp = a.grp AND b.account = 1 "
                "JOIN entities n ON n.id = a.entity_id AND n.kind IN ('ipv4', 'ipv6', 'endpoint')",
                (source_id,),
            )
            db.execute("DROP TABLE IF EXISTS temp.entity_group")
        self._update_entities(db)

    @staticmethod
    def _update_entities(db) -> None:
        """Totals and frequency marks of the entities in temp.touched."""
        db.execute(
            "UPDATE entities SET "
            "events = (SELECT COALESCE(SUM(events), 0) FROM entity_source s WHERE s.entity_id = entities.id), "
            "groups = (SELECT COALESCE(SUM(groups), 0) FROM entity_source s WHERE s.entity_id = entities.id), "
            "sources = (SELECT COUNT(*) FROM entity_source s WHERE s.entity_id = entities.id), "
            "first_ms = (SELECT MIN(first_ms) FROM entity_source s WHERE s.entity_id = entities.id), "
            "last_ms = (SELECT MAX(last_ms) FROM entity_source s WHERE s.entity_id = entities.id) "
            "WHERE id IN (SELECT id FROM temp.touched)"
        )
        db.execute(
            "UPDATE entities SET common = CASE "
            "WHEN kind IN ('msgid', 'queue', 'domain', 'host', 'url') THEN groups >= ? "
            "WHEN kind IN ('ipv4', 'ipv6', 'endpoint') THEN "
            "(SELECT COUNT(DISTINCT account_id) FROM ip_accounts WHERE ip_id = entities.id) >= ? "
            "ELSE 0 END WHERE id IN (SELECT id FROM temp.touched)",
            (COMMON_MIN_GROUPS, SHARED_IP_ACCOUNTS),
        )
        db.execute("INSERT OR REPLACE INTO meta VALUES ('common_threshold', ?)", (str(COMMON_MIN_GROUPS),))

    def _ensure_stats(self, db, tell=None) -> None:
        """Investigations made before the per-file statistics get them once."""
        if self.meta(db, "stats_version") == str(STATS_VERSION):
            return
        sources = [row[0] for row in db.execute("SELECT id FROM sources")]
        for index, source_id in enumerate(sources, 1):
            if tell is not None:
                tell(f"Untersuchung wird umgestellt ({index}/{len(sources)})")
            self._source_stats(db, source_id)
            stated = [row[0] for row in db.execute(
                "SELECT DISTINCT line_off FROM events WHERE source_id = ? AND raw_flag = 'exact' AND line_off IS NOT NULL",
                (source_id,),
            )]
            etypes = dict(db.execute(
                "SELECT etype, COUNT(*) FROM events WHERE source_id = ? GROUP BY etype", (source_id,)
            ).fetchall())
            db.execute("UPDATE sources SET stated = ?, etypes = ?, state = 'ready' WHERE id = ?",
                       (dumps(sorted(stated)), dumps(etypes), source_id))
        self._entity_stats(db, None)
        db.execute("INSERT OR REPLACE INTO meta VALUES ('stats_version', ?)", (str(STATS_VERSION),))
        db.commit()

    # -- time settings -----------------------------------------------------------

    def _naive_offset(self, db) -> tuple[int | None, str]:
        """The offset for lines without a zone: the user's choice, or the zone all
        explicit statements of this investigation agree on, or this computer's."""
        choice = self.meta(db, "default_tz", "auto")
        if choice.startswith("fixed:"):
            return int(choice[6:]), "source"
        if choice == "local":
            return None, "local"
        stated: set = set()
        for listed, detected in db.execute("SELECT stated, detected_offset FROM sources"):
            stated.update(json.loads(listed) if listed else ())
            if detected is not None:
                stated.add(detected)
        if len(stated) == 1:
            return stated.pop(), "inferred"
        return None, "local"

    def _retime(self, db, source_ids: list[int] | None = None) -> None:
        default_offset, default_flag = self._naive_offset(db)
        rows = db.execute("SELECT id, tz_mode, tz_offset, detected_offset, skew_ms FROM sources").fetchall()
        for source in rows:
            if source_ids is not None and source["id"] not in source_ids:
                continue
            source_id = source["id"]
            skew = source["skew_ms"] or 0
            if source["tz_mode"] == "fixed" and source["tz_offset"] is not None:
                offset, flag = source["tz_offset"], "source"
            elif source["detected_offset"] is not None:
                offset, flag = source["detected_offset"], "source"
            else:
                offset, flag = default_offset, default_flag
            db.execute(
                "UPDATE events SET off_min = line_off, ts_ms = wall_ms - line_off * 60000 + ?, "
                "sort_ms = wall_ms - line_off * 60000 + ?, ts_flag = 'exact' "
                "WHERE source_id = ? AND raw_flag = 'exact' AND line_off IS NOT NULL AND wall_ms IS NOT NULL",
                (skew, skew, source_id),
            )
            naive = (
                "UPDATE events SET off_min = ?, ts_ms = wall_ms - ? * 60000 + ?, sort_ms = wall_ms - ? * 60000 + ?, "
                "ts_flag = CASE WHEN raw_flag IN ('inherited', 'ambiguous') THEN raw_flag ELSE ? END "
                "WHERE source_id = ? AND (raw_flag != 'exact' OR line_off IS NULL) AND wall_ms IS NOT NULL"
            )
            if offset is not None:
                db.execute(naive, (offset, offset, skew, offset, skew, flag, source_id))
            else:
                # This computer's zone, summer time included: one update per
                # stretch of time with the same offset.
                for start, end, zone in self._local_ranges(db, source_id):
                    db.execute(naive + " AND wall_ms >= ? AND wall_ms < ?",
                               (zone, zone, skew, zone, skew, "local", source_id, start, end))
            db.execute(
                "UPDATE events SET ts_flag = CASE WHEN raw_flag = 'invalid' THEN 'invalid' ELSE 'none' END, "
                "ts_ms = NULL, sort_ms = ? WHERE source_id = ? AND wall_ms IS NULL",
                (SENTINEL, source_id),
            )
            self._source_stats(db, source_id)

    @staticmethod
    def _local_ranges(db, source_id: int) -> list[tuple[int, int, int]]:
        low = db.execute("SELECT MIN(wall_ms) FROM events WHERE source_id = ? AND wall_ms IS NOT NULL", (source_id,)).fetchone()[0]
        high = db.execute("SELECT MAX(wall_ms) FROM events WHERE source_id = ?", (source_id,)).fetchone()[0]
        if low is None:
            return []
        ranges: list[list[int]] = []
        hour = low // 3_600_000
        while hour <= high // 3_600_000:
            zone = local_offset(hour * 3_600_000)
            if ranges and ranges[-1][2] == zone:
                ranges[-1][1] = (hour + 1) * 3_600_000
            else:
                ranges.append([hour * 3_600_000, (hour + 1) * 3_600_000, zone])
            hour += 1
        return [tuple(item) for item in ranges]

    def set_time(self, source_id: int | None, mode: str, offset_min: int | None = None, skew_seconds: float = 0) -> None:
        """Time zone and clock correction for one source, or the default for lines without a zone."""
        with self.connect() as db:
            self._ensure_stats(db)
            before = self._naive_offset(db)
            if source_id is None:
                value = f"fixed:{int(offset_min)}" if mode == "fixed" and offset_min is not None else mode
                if value not in ("auto", "local") and not value.startswith("fixed:"):
                    raise InvestigationError("Unbekannte Zeiteinstellung.")
                db.execute("INSERT OR REPLACE INTO meta VALUES ('default_tz', ?)", (value,))
            else:
                if mode not in ("auto", "fixed"):
                    raise InvestigationError("Unbekannte Zeiteinstellung.")
                db.execute(
                    "UPDATE sources SET tz_mode = ?, tz_offset = ?, skew_ms = ? WHERE id = ?",
                    (mode, int(offset_min) if offset_min is not None else None, int(float(skew_seconds) * 1000), source_id),
                )
            if source_id is None or self._naive_offset(db) != before:
                self._retime(db)
                self._entity_stats(db, None)
            else:
                self._retime(db, [source_id])
                self._entity_stats(db, [source_id])
        self._changed()

    def remove_source(self, source_id: int) -> None:
        with self.connect() as db:
            self._ensure_stats(db)
            before = self._naive_offset(db)
            self._drop_source(db, source_id)
            if self._naive_offset(db) != before:
                self._retime(db)
                self._entity_stats(db, None)
        self._changed()

    def _drop_source(self, db, source_id: int) -> None:
        """Everything of one file, and the entities that occurred nowhere else."""
        db.execute("CREATE TEMP TABLE IF NOT EXISTS touched(id INTEGER PRIMARY KEY)")
        db.execute("DELETE FROM temp.touched")
        db.execute("INSERT OR IGNORE INTO temp.touched SELECT entity_id FROM entity_source WHERE source_id = ?", (source_id,))
        db.execute(
            "INSERT OR IGNORE INTO temp.touched SELECT DISTINCT o.entity_id FROM events e "
            "JOIN occurrences o ON o.event_id = e.id WHERE e.source_id = ?", (source_id,)
        )
        if FTS:
            # Every event has its entry in the text index, committed or not.
            db.execute(
                f"INSERT INTO events_fts(events_fts, rowid, message) SELECT 'delete', e.id, {TEXT_SQL} FROM events e "
                "WHERE e.source_id = ?", (source_id,)
            )
        _drop_texts(db, source_id)
        db.execute("DELETE FROM occurrences WHERE event_id IN (SELECT id FROM events WHERE source_id = ?)", (source_id,))
        db.execute("DELETE FROM events WHERE source_id = ?", (source_id,))
        for table in ("marks", "bins", "entity_source", "ip_accounts"):
            db.execute(f"DELETE FROM {table} WHERE source_id = ?", (source_id,))
        db.execute("DELETE FROM contexts WHERE key >= ? AND key < ?", (f"{source_id}:", f"{source_id};"))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'lines'").fetchone():
            db.execute("DELETE FROM lines WHERE source_id = ?", (source_id,))
        db.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        # Entities that occur nowhere any more go, and with them the decisions
        # about them: their numbers are given out again.
        db.execute("CREATE TEMP TABLE IF NOT EXISTS gone(id INTEGER PRIMARY KEY)")
        db.execute("DELETE FROM temp.gone")
        db.execute(
            "INSERT INTO temp.gone SELECT id FROM temp.touched t "
            "WHERE NOT EXISTS (SELECT 1 FROM occurrences o WHERE o.entity_id = t.id)"
        )
        for table in ("excluded", "included"):
            db.execute(f"DELETE FROM {table} WHERE entity_id IN (SELECT id FROM temp.gone)")
        db.execute("DELETE FROM link_excluded WHERE a IN (SELECT id FROM temp.gone) OR b IN (SELECT id FROM temp.gone)")
        db.execute("DELETE FROM entities WHERE id IN (SELECT id FROM temp.gone)")
        self._update_entities(db)

    # -- overview ----------------------------------------------------------------

    def overview(self) -> dict:
        with self.connect() as db:
            sources = [dict(row) for row in db.execute(
                "SELECT id, name, path, parser, parser_label, encoding, lines, events, first_ms, last_ms, "
                "detected_offset, tz_mode, tz_offset, skew_ms, state, time_flags, etypes FROM sources ORDER BY name"
            )]
            etype_counts: dict[str, int] = {}
            for source in sources:
                if source["time_flags"] is None and source["state"] == "ready":
                    self._source_stats(db, source["id"])
                    source["time_flags"] = db.execute(
                        "SELECT time_flags FROM sources WHERE id = ?", (source["id"],)).fetchone()[0]
                if source["etypes"] is None and source["state"] == "ready":
                    counts = dict(db.execute(
                        "SELECT etype, COUNT(*) FROM events WHERE source_id = ? GROUP BY etype", (source["id"],)
                    ).fetchall())
                    source["etypes"] = dumps(counts)
                    db.execute("UPDATE sources SET etypes = ? WHERE id = ?", (source["etypes"], source["id"]))
                source["kind"] = source_kind(source["name"])
                source["timeFlags"] = json.loads(source.pop("time_flags") or "{}")
                for etype, count in json.loads(source.pop("etypes") or "{}").items():
                    etype_counts[etype] = etype_counts.get(etype, 0) + count
                source["first"] = format_ms(source["first_ms"])
                source["last"] = format_ms(source["last_ms"])
            low = db.execute("SELECT MIN(sort_ms) FROM events").fetchone()[0]
            high = db.execute("SELECT MAX(sort_ms) FROM events WHERE sort_ms < ?", (SENTINEL,)).fetchone()[0]
            if low is not None and low >= SENTINEL:
                low = None
            counts = {
                "events": sum(source["events"] or 0 for source in sources),
                "entities": db.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
                "lines": sum(source["lines"] or 0 for source in sources),
            }
            etypes = [
                {"etype": etype, "label": logformats.ETYPE_LABELS.get(etype, etype), "count": count}
                for etype, count in sorted(etype_counts.items(), key=lambda item: -item[1])
            ]
            default_offset, default_flag = self._naive_offset(db)
            return {
                "id": self.id,
                "name": self.meta(db, "name", self.id),
                "sources": sources,
                "counts": counts,
                "first": format_ms(low), "last": format_ms(high),
                "firstMs": low, "lastMs": high,
                "etypes": etypes,
                "defaultTz": self.meta(db, "default_tz", "auto"),
                "naiveOffset": default_offset,
                "naiveFlag": default_flag,
                "commonThreshold": int(self.meta(db, "common_threshold", str(COMMON_MIN_GROUPS))),
                "fts": FTS,
                "version": self._version,
                "rate": float(self.meta(db, "rate", "0")) or None,
            }

    # -- search ------------------------------------------------------------------

    def suggest(self, text: str, limit: int = 12) -> list[dict]:
        text = text.strip()
        if len(text) < 2:
            return []
        with self.connect() as db:
            candidates = _normalized_candidates(text)
            rows = db.execute(
                f"SELECT * FROM entities WHERE value IN ({','.join('?' * len(candidates))}) ORDER BY events DESC",
                candidates,
            ).fetchall()
            # Values that start with the text, by an index range: most kinds are
            # kept in lower case, Message-IDs and devices as written.
            found = []
            for prefix in dict.fromkeys((text, text.lower())):
                found += db.execute(
                    "SELECT * FROM entities WHERE value >= ? AND value < ? AND kind NOT IN ('session', 'request') LIMIT 400",
                    (prefix, prefix + "\U0010ffff"),
                ).fetchall()
            rows += sorted(found, key=lambda row: -(row["events"] or 0))
            seen, result = set(), []
            for row in rows:
                if row["id"] not in seen:
                    seen.add(row["id"])
                    result.append(_entity_dict(row))
            return result[:limit]

    def find_entities(self, text: str) -> list[dict]:
        """Entities whose value is exactly what was typed, in any kind."""
        candidates = _normalized_candidates(text.strip())
        if not candidates:
            return []
        with self.connect() as db:
            rows = db.execute(
                f"SELECT * FROM entities WHERE value IN ({','.join('?' * len(candidates))}) ORDER BY events DESC",
                candidates,
            ).fetchall()
            return [_entity_dict(row) for row in rows]

    def search(
        self,
        query: str = "",
        entity_ids: list[int] | None = None,
        sources: list[int] | None = None,
        etypes: list[str] | None = None,
        min_severity: int = 1,
        time_from: int | None = None,
        time_to: int | None = None,
        levels: list[int] | None = None,
        temporal_seconds: int = 0,
        limit: int = 200,
        offset: int = 0,
        ids_only: bool = False,
    ) -> dict:
        """Events in time order. With entities, the trace around them with correlation levels.

        Typed text that is exactly a known identifier searches for it as an
        entity; next to chosen entities, text narrows their trace instead.
        """
        limit = max(1, min(int(limit), 5000 if ids_only else 1000))
        query = (query or "").strip()
        anchors: list[dict] = []
        text = query
        if not entity_ids and query:
            anchors = self.find_entities(query)
            entity_ids = [item["id"] for item in anchors]
            if entity_ids:
                text = ""
        with self.connect() as db:
            conditions, params = [], []
            trace = None
            mode = "all"
            # A trace is a few thousand events: read those, not the whole timeline.
            base = "events e"
            if entity_ids:
                mode = "trace"
                trace = self._trace(db, tuple(sorted(entity_ids)), temporal_seconds)
                db.execute("CREATE TEMP TABLE IF NOT EXISTS picked(id INTEGER PRIMARY KEY, level INTEGER)")
                db.execute("DELETE FROM temp.picked")
                wanted = set(levels or (DIRECT, STRONG, POSSIBLE))
                db.executemany(
                    "INSERT INTO temp.picked VALUES (?, ?)",
                    [(event_id, item[0]) for event_id, item in trace["events"].items() if item[0] in wanted],
                )
                base = "temp.picked p CROSS JOIN events e ON e.id = p.id"
                if not anchors:
                    anchors = [self._entity(db, entity_id) for entity_id in entity_ids]
            if text:
                mode = "text" if mode == "all" else mode
                if FTS:
                    expression, exact = _fts_query(text, self._fts_positions)
                    conditions.append("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
                    params.append(expression)
                    for word in exact:
                        conditions.append(f"{TEXT_SQL} LIKE ? ESCAPE '\\'")
                        params.append("%" + _like(word) + "%")
                else:
                    conditions.append(f"{TEXT_SQL} LIKE ? ESCAPE '\\'")
                    params.append("%" + _like(text) + "%")
            if sources:
                conditions.append(f"e.source_id IN ({','.join('?' * len(sources))})")
                params.extend(int(item) for item in sources)
            if etypes:
                conditions.append(f"e.etype IN ({','.join('?' * len(etypes))})")
                params.extend(etypes)
            if min_severity:
                conditions.append("e.severity >= ?")
                params.append(int(min_severity))
            if time_from is not None:
                conditions.append("e.sort_ms >= ? AND e.sort_ms < ?")
                params.extend((int(time_from), SENTINEL))
            if time_to is not None:
                conditions.append("e.sort_ms <= ?")
                params.append(int(time_to))
            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            order = "ORDER BY e.sort_ms, e.source_id, e.line_start"
            if ids_only:
                rows = db.execute(f"SELECT e.id FROM {base} {where} {order} LIMIT ?", [*params, limit]).fetchall()
                return {"ids": [row[0] for row in rows]}
            try:
                total = db.execute(
                    f"SELECT COUNT(*) FROM (SELECT 1 FROM {base} {where} LIMIT ?)", [*params, COUNT_CAP + 1]
                ).fetchone()[0]
                rows = db.execute(
                    f"SELECT {EVENT_COLUMNS}, s.name AS source_name FROM {base} JOIN sources s ON s.id = e.source_id {where} "
                    f"{order} LIMIT ? OFFSET ?",
                    [*params, limit, int(offset)],
                ).fetchall()
            except sqlite3.OperationalError as error:
                raise InvestigationError(f"Die Suche konnte nicht ausgeführt werden: {error}") from error
            result = [self._event_row(db, row, trace) for row in rows]
            # Few hits are counted exactly; many over the stored time bins, as
            # far as the filters allow; text, types and traces with very many
            # hits go without the strip rather than scan the whole index.
            if total <= COUNT_CAP:
                histogram = self._histogram(db, base, where, params, trace is not None)
            elif not text and not etypes and trace is None:
                histogram = self._binned_histogram(db, sources, int(min_severity or 0), time_from, time_to)
            else:
                histogram = None
            summary = None
            if trace is not None:
                summary = {LEVEL_LABELS[level]: sum(1 for item in trace["events"].values() if item[0] == level)
                           for level in (DIRECT, STRONG, POSSIBLE)}
            return {
                "mode": mode, "anchors": anchors, "total": total, "offset": offset, "limit": limit,
                "rows": result, "levels": summary, "truncated": bool(trace and trace["truncated"]),
                "histogram": histogram,
            }

    @staticmethod
    def _histogram(db, base: str, where: str, params: list, traced: bool, buckets: int = 72) -> dict | None:
        """Events over time for the overview strip: per bucket, by level when tracing."""
        clause = f"{where} AND e.ts_ms IS NOT NULL" if where else "WHERE e.ts_ms IS NOT NULL"
        span = db.execute(f"SELECT MIN(e.ts_ms), MAX(e.ts_ms) FROM {base} {clause}", params).fetchone()
        if span[0] is None:
            return None
        start, end = span[0], span[1]
        size = max(1000, -(-(end - start + 1) // buckets))
        level = "p.level" if traced else "0"
        counts = [[0, 0, 0, 0] for _ in range((end - start) // size + 1)]
        for index, level_value, count in db.execute(
            f"SELECT (e.ts_ms - ?) / ?, {level}, COUNT(*) FROM {base} {clause} GROUP BY 1, 2",
            [start, size, *params],
        ):
            counts[int(index)][int(level_value)] += count
        return {"from": start, "bucketMs": size, "counts": counts}

    @staticmethod
    def _binned_histogram(db, sources, min_severity, time_from, time_to, buckets: int = 72) -> dict | None:
        """The strip from the stored ten-minute bins: for many hits, at ten minutes' resolution."""
        conditions, params = ["severity >= ?"], [min_severity]
        if sources:
            conditions.append(f"source_id IN ({','.join('?' * len(sources))})")
            params.extend(int(item) for item in sources)
        if time_from is not None:
            conditions.append("bin >= ?")
            params.append(int(time_from) // BIN_MS)
        if time_to is not None:
            conditions.append("bin <= ?")
            params.append(int(time_to) // BIN_MS)
        rows = db.execute(
            f"SELECT bin, SUM(n) FROM bins WHERE {' AND '.join(conditions)} GROUP BY bin ORDER BY bin", params
        ).fetchall()
        if not rows:
            return None
        start = rows[0][0] * BIN_MS
        end = (rows[-1][0] + 1) * BIN_MS - 1
        raw = -(-(end - start + 1) // buckets)
        size = max(BIN_MS, -(-raw // BIN_MS) * BIN_MS)
        counts = [[0, 0, 0, 0] for _ in range((end - start) // size + 1)]
        for bin_, count in rows:
            counts[(bin_ * BIN_MS - start) // size][0] += count
        return {"from": start, "bucketMs": size, "counts": counts, "approximate": True}

    def _event_row(self, db, row, trace=None) -> dict:
        found = db.execute(
            "SELECT n.id, n.kind, n.value, n.display, n.common, n.generic, o.role FROM occurrences o "
            "JOIN entities n ON n.id = o.entity_id WHERE o.event_id = ? ORDER BY n.kind", (row["id"],)
        ).fetchall()
        chips = [
            {"id": item["id"], "kind": item["kind"], "value": item["value"], "display": item["display"],
             "role": item["role"], "common": item["common"], "generic": item["generic"]}
            for item in found if item["kind"] not in WEAK_KINDS
        ]
        text = row["message"]
        first_line = text.split("\n", 1)[0]
        data = {
            "id": row["id"], "source": row["source_name"], "sourceId": row["source_id"],
            "sourceKind": source_kind(row["source_name"]), "summary": _LEADING_TIME.sub("", first_line, count=1)[:400],
            "line": row["line_start"], "lineEnd": row["line_end"],
            "ts": row["ts_ms"], "time": format_ms(row["ts_ms"], row["off_min"]), "offset": row["off_min"],
            "timeFlag": row["ts_flag"], "etype": row["etype"],
            "etypeLabel": logformats.ETYPE_LABELS.get(row["etype"], row["etype"]),
            "severity": row["severity"], "text": first_line[:400],
            "lines": row["line_end"] - row["line_start"] + 1, "context": row["ctx"],
            "entities": chips[:12],
        }
        if trace is not None and row["id"] in trace["events"]:
            level, basis, hop = trace["events"][row["id"]]
            data.update(level=level, levelLabel=LEVEL_LABELS[level], basis=basis, hop=hop)
        return data

    # -- detail ------------------------------------------------------------------

    def event_detail(self, event_id: int, context_lines: int = 6, anchor_ids: list[int] | None = None) -> dict:
        with self.connect() as db:
            row = db.execute(
                f"SELECT {EVENT_COLUMNS}, s.name AS source_name, s.path AS source_path, s.size AS source_size, "
                "s.mtime_ns AS source_mtime, s.encoding AS source_encoding FROM events e "
                "JOIN sources s ON s.id = e.source_id WHERE e.id = ?", (event_id,)
            ).fetchone()
            if row is None:
                raise InvestigationError("Ereignis nicht gefunden.")
            trace = self._trace(db, tuple(sorted(anchor_ids)), 0) if anchor_ids else None
            data = self._event_row(db, row, trace)
            data["text"] = row["message"]
            data["path"] = row["source_path"]
            data["timeFlagLabel"] = TIME_FLAG_LABELS.get(row["ts_flag"], row["ts_flag"])
            data["wall"] = format_ms(row["wall_ms"]) if row["wall_ms"] is not None else ""
            first = max(1, row["line_start"] - context_lines)
            last = row["line_end"] + context_lines
            lines, note = self._context_lines(db, row, first, last)
            data["contextLines"] = [
                {"line": number, "text": text, "own": row["line_start"] <= number <= row["line_end"]}
                for number, text in lines
            ]
            data["contextNote"] = note
            data["spans"] = [
                {"start": item.start, "end": item.end, "kind": item.kind, "value": item.value}
                for item in entities.extract(row["message"]) if item.start >= 0
            ]
            if row["ctx"]:
                data["contextSize"] = db.execute("SELECT COUNT(*) FROM events WHERE ctx = ?", (row["ctx"],)).fetchone()[0]
                label = db.execute(
                    "SELECT n.display FROM contexts c JOIN entities n ON n.value = c.key "
                    "AND n.kind IN ('session', 'request') WHERE c.id = ?", (row["ctx"],)
                ).fetchone()
                data["contextLabel"] = label[0] if label else "Verarbeitungsblock"
            return data

    @staticmethod
    def _context_lines(db, row, first: int, last: int) -> tuple[list[tuple[int, str]], str]:
        """The lines around an event as the file has them, and a note when they come from elsewhere.

        The index keeps every event's own text, not the file's every line. The
        surroundings are read from the original, starting at the nearest kept
        byte offset; when the original has changed or is gone, the stored
        lines of the event and its neighbours stand in.
        """
        path = Path(row["source_path"])
        try:
            stat = path.stat()
            same = stat.st_size == row["source_size"] and (row["source_mtime"] in (None, stat.st_mtime_ns))
        except OSError:
            same = False
        mark = db.execute(
            "SELECT lineno, offset FROM marks WHERE source_id = ? AND lineno <= ? ORDER BY lineno DESC LIMIT 1",
            (row["source_id"], first),
        ).fetchone()
        encoding = row["source_encoding"]
        if same and mark is not None and logformats.binary_lines(encoding):
            lines = []
            with open(path, "rb") as handle:
                raw_lines = logformats.read_raw_lines(handle, mark["offset"], bom=logformats.bom_of(encoding))
                for number, (_, raw) in enumerate(raw_lines, mark["lineno"]):
                    if number > last:
                        break
                    if number >= first:
                        lines.append((number, raw.decode(encoding, "replace")))
            return lines, ""
        if db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'lines'").fetchone():
            stored = db.execute(
                "SELECT lineno, text FROM lines WHERE source_id = ? AND lineno BETWEEN ? AND ? ORDER BY lineno",
                (row["source_id"], first, last),
            ).fetchall()
            if stored:
                return [(item[0], item[1]) for item in stored], ""
        lines = []
        for event in db.execute(
            f"SELECT e.line_start, {TEXT_SQL} AS message FROM events e WHERE e.source_id = ? AND e.line_end >= ? "
            "AND e.line_start <= ? ORDER BY e.line_start", (row["source_id"], first, last),
        ):
            for number, text in enumerate(event["message"].split("\n"), event["line_start"]):
                if first <= number <= last:
                    lines.append((number, text))
        note = ("Die Originaldatei ist nicht mehr erreichbar oder wurde geändert. Gezeigt werden die gespeicherten "
                "Zeilen dieses und der benachbarten Ereignisse; Leerzeilen und Zeilennummern können abweichen.")
        return lines, note

    def context_events(self, event_id: int, limit: int = 500) -> list[dict]:
        """All events of the session, request or block an event belongs to."""
        with self.connect() as db:
            row = db.execute("SELECT ctx FROM events WHERE id = ?", (event_id,)).fetchone()
            if row is None or not row["ctx"]:
                return []
            rows = db.execute(
                f"SELECT {EVENT_COLUMNS}, s.name AS source_name FROM events e JOIN sources s ON s.id = e.source_id "
                "WHERE e.ctx = ? ORDER BY e.line_start LIMIT ?", (row["ctx"], limit)
            ).fetchall()
            return [self._event_row(db, item) for item in rows]

    def _entity(self, db, entity_id: int) -> dict:
        row = db.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if row is None:
            raise InvestigationError("Entität nicht gefunden.")
        data = _entity_dict(row)
        data["excluded"] = bool(db.execute("SELECT 1 FROM excluded WHERE entity_id = ?", (entity_id,)).fetchone())
        data["included"] = bool(db.execute("SELECT 1 FROM included WHERE entity_id = ?", (entity_id,)).fetchone())
        return data

    def entity_detail(self, entity_id: int) -> dict:
        with self.connect() as db:
            data = self._entity(db, entity_id)
            data["bySource"] = [
                {"sourceId": row[0], "source": row[1], "events": row[2], "first": format_ms(row[3]), "last": format_ms(row[4])}
                for row in db.execute(
                    "SELECT s.id, s.name, es.events, es.first_ms, es.last_ms FROM entity_source es "
                    "JOIN sources s ON s.id = es.source_id WHERE es.entity_id = ? ORDER BY es.events DESC LIMIT 200",
                    (entity_id,),
                )
            ]
            # Roles as the first hundred thousand occurrences show them.
            data["roles"] = dict(db.execute(
                "SELECT role, COUNT(*) FROM (SELECT role FROM occurrences WHERE entity_id = ? LIMIT 100000) "
                "WHERE role != '' GROUP BY role", (entity_id,)
            ).fetchall())
            data["related"] = self._related(db, entity_id, 40)
            trace = self._trace(db, (entity_id,), 0)
            data["levels"] = {LEVEL_LABELS[level]: sum(1 for item in trace["events"].values() if item[0] == level)
                              for level in (DIRECT, STRONG, POSSIBLE)}
            data["possible"] = self._trace_entities(db, trace, (STRONG, POSSIBLE), entity_id, 15)
            return data

    def _related(self, db, entity_id: int, limit: int, kinds: set[str] | None = None) -> list[dict]:
        """Entities in the same events, sessions, requests or blocks: direct relations."""
        excluded_links = self._excluded_links(db)
        db.execute("DROP TABLE IF EXISTS temp.near")
        db.execute(
            "CREATE TEMP TABLE near AS SELECT event_id AS id FROM occurrences WHERE entity_id = ? LIMIT 20000",
            (entity_id,),
        )
        db.execute(
            "INSERT INTO temp.near SELECT id FROM events WHERE ctx IN (SELECT DISTINCT ctx FROM events "
            "WHERE id IN (SELECT id FROM temp.near) AND ctx IS NOT NULL) LIMIT 50000"
        )
        rows = db.execute(
            "SELECT n.*, COUNT(DISTINCT o.event_id) AS shared FROM (SELECT DISTINCT id FROM temp.near) m "
            "JOIN occurrences o ON o.event_id = m.id JOIN entities n ON n.id = o.entity_id WHERE o.entity_id != ? "
            "GROUP BY o.entity_id ORDER BY shared DESC LIMIT ?",
            (entity_id, limit * 4),
        ).fetchall()
        db.execute("DROP TABLE IF EXISTS temp.near")
        result = []
        for row in rows:
            if row["kind"] in WEAK_KINDS or (kinds and row["kind"] not in kinds):
                continue
            if (min(entity_id, row["id"]), max(entity_id, row["id"])) in excluded_links:
                continue
            item = _entity_dict(row)
            item.update(shared=row["shared"], level=DIRECT, levelLabel=LEVEL_LABELS[DIRECT])
            result.append(item)
            if len(result) >= limit:
                break
        return result

    def _trace_entities(self, db, trace, levels, anchor: int, limit: int) -> list[dict]:
        picked = [event_id for event_id, item in trace["events"].items() if item[0] in levels][:5000]
        if not picked:
            return []
        db.execute("CREATE TEMP TABLE IF NOT EXISTS picked2(id INTEGER PRIMARY KEY)")
        db.execute("DELETE FROM temp.picked2")
        db.executemany("INSERT INTO temp.picked2 VALUES (?)", [(item,) for item in picked])
        rows = db.execute(
            "SELECT n.*, COUNT(DISTINCT o.event_id) AS shared FROM temp.picked2 p JOIN occurrences o ON o.event_id = p.id "
            "JOIN entities n ON n.id = o.entity_id WHERE o.entity_id != ? AND n.kind NOT IN "
            "('status', 'code', 'pid', 'port', 'session', 'request') GROUP BY n.id ORDER BY shared DESC LIMIT ?",
            (anchor, limit),
        ).fetchall()
        return [dict(_entity_dict(row), shared=row["shared"]) for row in rows]

    # -- correlation ---------------------------------------------------------------

    def _excluded_links(self, db) -> set[tuple[int, int]]:
        return {(row[0], row[1]) for row in db.execute("SELECT a, b FROM link_excluded")}

    def _usable(self, db) -> tuple[set[int], set[int]]:
        excluded = {row[0] for row in db.execute("SELECT entity_id FROM excluded")}
        included = {row[0] for row in db.execute("SELECT entity_id FROM included")}
        return excluded, included

    def _trace(self, db, anchors: tuple[int, ...], temporal_seconds: int = 0, window_seconds: int = 300) -> dict:
        key = (anchors, temporal_seconds, window_seconds, self._version)
        cached = self._trace_cache.get(key)
        if cached is not None:
            return cached
        excluded, included = self._usable(db)
        excluded_links = self._excluded_links(db)
        info = {row["id"]: row for row in db.execute(
            f"SELECT * FROM entities WHERE id IN ({','.join('?' * len(anchors))})", anchors
        )}

        def usable(row) -> bool:
            if row["id"] in excluded:
                return False
            return row["id"] in included or not (row["common"] or row["generic"])

        def label(row) -> str:
            return f"{KIND_LABELS.get(row['kind'], row['kind'])} {row['display'] or row['value']}"

        events: dict[int, tuple[int, str, int]] = {}
        basis = {entity_id: f"enthält {label(row)}" for entity_id, row in info.items()}
        frontier = set(info)
        seen = set(frontier)
        truncated = False
        hop = 0
        while frontier and hop <= 3:
            marks = ",".join("?" * len(frontier))
            added: list[int] = []
            for event_id, entity_id in db.execute(
                f"SELECT event_id, entity_id FROM occurrences WHERE entity_id IN ({marks}) LIMIT 30000", tuple(frontier)
            ):
                if event_id not in events:
                    events[event_id] = (DIRECT, basis.get(entity_id, ""), hop)
                    added.append(event_id)
            if added:
                db.execute("CREATE TEMP TABLE IF NOT EXISTS added(id INTEGER PRIMARY KEY)")
                db.execute("DELETE FROM temp.added")
                db.executemany("INSERT OR IGNORE INTO temp.added VALUES (?)", [(item,) for item in added])
                # Whole sessions, requests and blocks, read before temp.added grows.
                same_context = db.execute(
                    "SELECT id FROM events WHERE ctx IN (SELECT DISTINCT ctx FROM events "
                    "WHERE id IN (SELECT id FROM temp.added) AND ctx IS NOT NULL) LIMIT 60000"
                ).fetchall()
                truncated = truncated or len(same_context) >= 60000
                fresh = [event_id for (event_id,) in same_context if event_id not in events]
                for event_id in fresh:
                    events[event_id] = (DIRECT, "gleiche Sitzung, Request oder Verarbeitung", hop)
                db.executemany("INSERT OR IGNORE INTO temp.added VALUES (?)", [(item,) for item in fresh])
                # Joined from the events outward; "IN (SELECT …)" makes SQLite try
                # every message id against every event instead.
                pivots = db.execute(
                    "SELECT DISTINCT n.* FROM temp.added a JOIN occurrences o ON o.event_id = a.id "
                    "JOIN entities n ON n.id = o.entity_id WHERE n.kind IN ('msgid', 'queue') AND o.role != 'context'"
                ).fetchall()
            else:
                pivots = []
            frontier = set()
            for row in pivots:
                if row["id"] in seen or not usable(row):
                    continue
                if any((min(row["id"], anchor), max(row["id"], anchor)) in excluded_links for anchor in anchors):
                    continue
                seen.add(row["id"])
                frontier.add(row["id"])
                basis[row["id"]] = f"gleiche {label(row)}"
            if len(events) > 50000:
                truncated = True
                break
            hop += 1

        # Strong and possible: parties the searched entity's own events name,
        # met again outside the explicit chain. Only hop 0 widens: an address
        # seen in a message's relay hop says nothing about the searched account.
        direct_ids = list(events)
        db.execute("CREATE TEMP TABLE IF NOT EXISTS direct(id INTEGER PRIMARY KEY)")
        db.execute("DELETE FROM temp.direct")
        db.executemany("INSERT INTO temp.direct VALUES (?)", [(item,) for item in direct_ids])
        db.execute("CREATE TEMP TABLE IF NOT EXISTS seed(id INTEGER PRIMARY KEY)")
        db.execute("DELETE FROM temp.seed")
        db.executemany(
            "INSERT INTO temp.seed VALUES (?)", [(event_id,) for event_id, item in events.items() if item[2] == 0]
        )
        link_kinds = ",".join(f"'{kind}'" for kind in sorted(LINK_KINDS))
        # Sender and recipient of a message are its parties: for a message they
        # point to its other traces, for a person they are somebody else.
        parties = "" if any(row["kind"] not in LINK_KINDS for row in info.values()) else \
            "AND o.role NOT IN ('from', 'to', 'return-path')"
        identities = db.execute(
            f"SELECT n.*, group_concat(e.ts_ms) AS times FROM temp.seed s JOIN occurrences o ON o.event_id = s.id "
            f"JOIN entities n ON n.id = o.entity_id JOIN events e ON e.id = o.event_id "
            f"WHERE n.kind IN ({link_kinds}) AND o.role != 'server' {parties} GROUP BY n.id"
        ).fetchall()
        window = window_seconds * 1000
        shared: dict[int, list[tuple[str, bool, bool]]] = {}
        for row in identities:
            if row["id"] in excluded or row["id"] in info:
                continue
            if any((min(row["id"], anchor), max(row["id"], anchor)) in excluded_links for anchor in anchors):
                continue
            times = sorted(int(item) for item in (row["times"] or "").split(",") if item)
            good = usable(row)
            if good:
                candidates = db.execute(
                    "SELECT e.id, e.ts_ms FROM occurrences o JOIN events e ON e.id = o.event_id "
                    "WHERE o.entity_id = ? AND o.role != 'server' LIMIT 20000", (row["id"],)
                ).fetchall()
            elif times and row["kind"] in IP_KINDS and not row["generic"]:
                # A shared address (NAT, a relay) only hints at anything close in
                # time, so only look there.
                candidates = db.execute(
                    "SELECT e.id, e.ts_ms FROM occurrences o JOIN events e ON e.id = o.event_id WHERE o.entity_id = ? "
                    "AND o.role != 'server' AND e.ts_ms BETWEEN ? AND ? LIMIT 20000",
                    (row["id"], times[0] - window, times[-1] + window),
                ).fetchall()
            else:
                continue
            for event_id, ts in candidates:
                if event_id in events:
                    continue
                near = ts is not None and _near(times, ts, window)
                if not good and not near:
                    continue
                shared.setdefault(event_id, []).append((label(row), good, near))
        for event_id, items in shared.items():
            # Strong needs closeness in time as well: the same two parties also
            # write each other days apart, and that is another message.
            good = [item for item in items if item[1]]
            near = any(item[2] for item in good)
            names = " und ".join(sorted({item[0] for item in (good or items)})[:3])
            if good and near:
                events[event_id] = (STRONG, f"gleiche {names}, zeitlich nah (±{window_seconds // 60} min)", 9)
            elif good:
                events[event_id] = (POSSIBLE, f"gleiche {names}, zeitlich entfernt", 9)
            else:
                events[event_id] = (POSSIBLE, f"geteilte Adresse {names}, zeitlich nah", 9)

        if temporal_seconds and direct_ids:
            sources = {row[0] for row in db.execute("SELECT DISTINCT source_id FROM events WHERE id IN (SELECT id FROM temp.direct)")}
            times = sorted(row[0] for row in db.execute(
                "SELECT ts_ms FROM events WHERE id IN (SELECT id FROM temp.direct) AND ts_ms IS NOT NULL"
            ))
            if times:
                span = temporal_seconds * 1000
                for event_id, ts, source_id in db.execute(
                    "SELECT id, ts_ms, source_id FROM events WHERE sort_ms BETWEEN ? AND ? AND severity >= 1 LIMIT 50000",
                    (times[0] - span, times[-1] + span),
                ):
                    if event_id in events or source_id in sources or not _near(times, ts, span):
                        continue
                    events[event_id] = (POSSIBLE, f"nur zeitliche Nähe (±{temporal_seconds} s), anderer Log", 9)
        result = {"events": events, "truncated": truncated}
        if len(self._trace_cache) > 20:
            self._trace_cache.clear()
        self._trace_cache[key] = result
        return result

    # -- graph -----------------------------------------------------------------

    def graph(self, entity_id: int, kinds: list[str] | None = None, limit: int = 24) -> dict:
        """The entity, its direct neighbours, and one step further behind messages and sessions."""
        wanted = set(kinds) if kinds else None
        with self.connect() as db:
            anchor = self._entity(db, entity_id)
            nodes = {entity_id: dict(anchor, anchor=True)}
            for item in self._related(db, entity_id, limit, wanted):
                nodes.setdefault(item["id"], item)
            for item in list(nodes.values()):
                if item["id"] == entity_id or item["kind"] not in UNIQUE_KINDS:
                    continue
                for second in self._related(db, item["id"], 4, wanted):
                    if len(nodes) >= limit + 16:
                        break
                    nodes.setdefault(second["id"], second)
            ids = list(nodes)
            marks = ",".join("?" * len(ids))
            excluded_links = self._excluded_links(db)
            edges = []
            for a, b, weight in db.execute(
                f"SELECT o1.entity_id, o2.entity_id, COUNT(DISTINCT o1.event_id) FROM occurrences o1 "
                f"JOIN occurrences o2 ON o2.event_id = o1.event_id AND o2.entity_id > o1.entity_id "
                f"WHERE o1.entity_id IN ({marks}) AND o2.entity_id IN ({marks}) GROUP BY o1.entity_id, o2.entity_id",
                [*ids, *ids],
            ):
                if (a, b) in excluded_links:
                    continue
                edges.append({"a": a, "b": b, "weight": weight})
            return {"nodes": list(nodes.values()), "edges": edges, "anchor": entity_id}

    def flag_entity(self, entity_id: int, action: str) -> dict:
        with self.connect() as db:
            db.execute("DELETE FROM excluded WHERE entity_id = ?", (entity_id,))
            db.execute("DELETE FROM included WHERE entity_id = ?", (entity_id,))
            if action == "exclude":
                db.execute("INSERT INTO excluded VALUES (?)", (entity_id,))
            elif action == "include":
                db.execute("INSERT INTO included VALUES (?)", (entity_id,))
            elif action != "reset":
                raise InvestigationError("Unbekannte Aktion.")
            data = self._entity(db, entity_id)
        self._trace_cache.clear()
        return data

    def exclude_link(self, a: int, b: int, undo: bool = False) -> None:
        pair = (min(int(a), int(b)), max(int(a), int(b)))
        with self.connect() as db:
            if undo:
                db.execute("DELETE FROM link_excluded WHERE a = ? AND b = ?", pair)
            else:
                db.execute("INSERT OR IGNORE INTO link_excluded VALUES (?, ?)", pair)
        self._trace_cache.clear()

    # -- export ------------------------------------------------------------------

    def export_text(self, event_ids: list[int], mapping: Mapping, limit: int = 5000) -> dict:
        """The chosen events, masked for an outside analysis, with everything a reviewer must know.

        Placeholders come from the mapping, so the same value gets the same
        placeholder as in any earlier export and can be restored locally. The
        result is blocked while an original value of the events is still
        readable in it, and flagged for review when the general check finds
        anything that still looks personal.
        """
        if not event_ids:
            raise InvestigationError("Keine Ereignisse für den Export gewählt.")
        event_ids = [int(item) for item in event_ids][:limit]
        with self.connect() as db:
            db.execute("CREATE TEMP TABLE IF NOT EXISTS chosen(id INTEGER PRIMARY KEY)")
            db.execute("DELETE FROM temp.chosen")
            db.executemany("INSERT OR IGNORE INTO temp.chosen VALUES (?)", [(item,) for item in event_ids])
            rows = db.execute(
                f"SELECT {EVENT_COLUMNS}, s.parser_label, s.name AS source_name FROM events e "
                "JOIN sources s ON s.id = e.source_id "
                "WHERE e.id IN (SELECT id FROM temp.chosen) ORDER BY e.sort_ms, e.source_id, e.line_start"
            ).fetchall()
            sensitive = db.execute(
                "SELECT DISTINCT n.kind, n.value, n.display, n.generic FROM temp.chosen c "
                "JOIN occurrences o ON o.event_id = c.id JOIN entities n ON n.id = o.entity_id"
            ).fetchall()
        # Sources go by alias; the log type from the file name says which log it was.
        aliases: dict[int, str] = {}
        legend = []
        for row in rows:
            if row["source_id"] not in aliases:
                aliases[row["source_id"]] = f"Q{len(aliases) + 1}"
                legend.append(f"{aliases[row['source_id']]} = {source_kind(row['source_name'])} ({row['parser_label']})")
        lines = []
        for row in rows:
            stamp = format_ms(row["ts_ms"], row["off_min"]) if row["ts_ms"] is not None else "no time"
            zone = _zone(row["off_min"]) if row["ts_ms"] is not None else ""
            body = row["message"].replace("\n", "\n    ")
            lines.append(f"{stamp}{zone} {aliases[row['source_id']]}: {body}")
        original = "\n".join(lines)

        # Identifiers the anonymizer cannot know by their shape are replaced as own
        # terms: accounts, devices, host names and the one-word host of a URL.
        # System names such as "postmaster" belong to nobody and stay.
        plain: set[str] = set()
        for item in sensitive:
            if item["kind"] in ("account", "device", "host") and not item["generic"]:
                plain.update(value for value in (item["value"], item["display"]) if value)
            elif item["kind"] == "url":
                # A host the address rules do not take: one word, a trailing dot, no real ending.
                host = _url_host(item["value"]).rstrip(".")
                if host and entities.normalize_ip(host) is None and not entities.is_domain(host):
                    plain.add(host)
        # Guarded like own terms: a name inside a mail address or a domain is left
        # to the address rule, which masks the address as a whole.
        options = Options(extra_patterns=tuple(
            rf"(?<![\w@])(?<!\w\.){re.escape(value)}(?!\w)(?!@)(?!\.[\w-])"
            for value in sorted(plain, key=len, reverse=True) if len(value) >= 3
        ))
        header = (
            "# LogMasque export for external analysis\n"
            f"# {len(rows)} events, values replaced by consistent placeholders.\n"
            f"# Sources: {'; '.join(legend)}"
        )
        engine = Anonymizer(mapping, options)
        engine.learn_text(original)
        masked = "\n".join(engine.process_line(line) for line in (header + "\n" + original).split("\n"))

        # The patterns judge a value by its surroundings and miss it glued to a
        # word or behind an underscore. The values of these events are known, so
        # whatever is left of them gets the same placeholder; what the engine
        # cannot replace either blocks the export. A value on the never-replace
        # list stays by the user's own decision.
        candidates = []
        for item in sensitive:
            if item["kind"] not in SENSITIVE_KINDS or (item["generic"] and item["kind"] in ("account", "device", "host")):
                continue
            for value in {item["value"], (item["display"] or "").strip("<>[]")}:
                if len(value) >= 4 and not _OWN_OUTPUT.fullmatch(value) and not _kept(item["kind"], value, mapping):
                    candidates.append((item["kind"], value))
        masked = _sweep(masked, candidates, engine)
        # Masking a neighbour can lay a value open that its surroundings hid
        # before ("…1.2.3.4host.example…"); one more round covers those.
        candidates += [(found.kind, found.display or found.value) for found in _readable(masked, mapping)]
        masked = _sweep(masked, candidates, engine)

        leaks: list[dict] = []
        lowered = masked.lower()
        for kind, value in candidates:
            if value.lower() in lowered and _bounded(kind, value).search(masked):
                if not any(leak["value"].lower() == value.lower() for leak in leaks):
                    leaks.append({"kind": KIND_LABELS.get(kind, kind), "type": kind, "value": value})
        for found in _readable(masked, mapping):
            if not any(leak["value"].lower() == found.value.lower() for leak in leaks):
                leaks.append({"kind": KIND_LABELS.get(found.kind, found.kind), "type": found.kind, "value": found.value})
        review = find_leaks(masked)
        text = masked
        return {
            "text": text,
            "marks": _marks(text, leaks),
            "events": len(rows),
            "stats": {name: count for name, count in engine.stats.items() if count},
            "blocked": bool(leaks),
            "leaks": leaks[:50],
            "review": review,
            "needsReview": bool(review),
        }


# -- helpers -----------------------------------------------------------------------


# The time at the start of a line, in the layouts the formats read; the list
# shows it in its own column, so the message goes without it.
_LEADING_TIME = re.compile(
    r"^(?:\[?(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) )?\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?\]?:?"
    r"(?: \| \w+ \|)?"
    r"|\d{6} \d{9}"
    r"|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \w{3} [ \d]\d \d\d:\d\d:\d\d \d{4} ->"
    r"|\d\d\.\d\d\.\d{4}[ ,]+\d\d:\d\d:\d\d(?:[.,]\d+)?)\s*"
)


def source_kind(name: str) -> str:
    """The log type a file name states, without its dates: "MDaemon-AntiVirus", "WebAdmin-HTTP"."""
    stem = PurePath(name.replace("\\", "/")).stem
    for pattern in DATE_PATTERNS:
        stem = pattern.sub("-", stem)
    return re.sub(r"[-_. ]{2,}", "-", stem).strip("-_. ") or "Log"


def _sweep(text: str, candidates: list[tuple[str, str]], engine: Anonymizer) -> str:
    """Replace what is left of known values with the placeholder the engine gives them."""
    lowered = text.lower()
    for kind, value in sorted(set(candidates), key=lambda candidate: len(candidate[1]), reverse=True):
        if value.lower() not in lowered:
            continue
        pattern = _bounded(kind, value)
        if not pattern.search(text):
            continue
        replacement = engine.process_line(value)
        if replacement.lower() != value.lower():
            text = pattern.sub(lambda _, token=replacement: token, text)
            lowered = text.lower()
    return text


def _readable(text: str, mapping: Mapping) -> list[entities.Found]:
    """Identifiers the rules still find in a masked text, minus own placeholders and kept values."""
    return [
        found for found in entities.extract(text)
        if found.kind in SENSITIVE_KINDS
        and not _OWN_OUTPUT.search(found.value)
        and not _kept(found.kind, found.value, mapping) and not _kept(found.kind, found.display or found.value, mapping)
    ]


def _kept(kind: str, value: str, mapping: Mapping) -> bool:
    """A value on the never-replace list; an address with a port when its address is on it."""
    if mapping.is_ignored(value):
        return True
    if kind == "endpoint" and ":" in value:
        address = value.rsplit(":", 1)[0].strip("[]")
        return mapping.is_ignored(address)
    return False


def _bounded(kind: str, value: str) -> re.Pattern:
    """The value as a whole: "192.0.2.1" not inside "192.0.2.10", a name not inside a longer word."""
    escaped = re.escape(value)
    if kind == "ipv4" or (kind == "endpoint" and not value.startswith("[")):
        return re.compile(rf"(?<![\d.]){escaped}(?!\d)(?!\.\d)")
    if kind in ("ipv6", "endpoint"):
        return re.compile(rf"(?<![0-9A-Fa-f:]){escaped}(?![0-9A-Fa-f])(?!:[0-9A-Fa-f])", re.IGNORECASE)
    return re.compile(rf"(?<![A-Za-z0-9.-]){escaped}(?![A-Za-z0-9-])(?!\.[A-Za-z0-9])", re.IGNORECASE)


def _url_host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _marks(text: str, leaks: list[dict], limit: int = 2000) -> list[dict]:
    """Where in the export a reviewer has to look: leaks block, findings ask for a look."""
    marks: list[dict] = []
    for leak in leaks:
        for match in _bounded(leak["type"], leak["value"]).finditer(text):
            marks.append({"start": match.start(), "end": match.end(), "category": "Leak", "label": leak["kind"], "leak": True})
            if len(marks) >= limit:
                break
    checker = Anonymizer(Mapping(), Options())
    checker.learn_text(text)
    offset = 0
    for line in text.split("\n"):
        position = offset
        for segment in checker.segments(line):
            piece = segment.original if segment.category else segment.text
            if segment.category and not _OWN_OUTPUT.fullmatch(segment.original):
                marks.append({"start": position, "end": position + len(piece), "category": segment.category, "leak": False})
            position += len(piece)
        for _, regex in _SECRET_HINTS:
            for match in regex.finditer(line):
                marks.append({"start": offset + match.start(), "end": offset + match.end(), "category": "Secret", "leak": False})
        offset += len(line) + 1
        if len(marks) >= limit:
            break
    marks.sort(key=lambda item: (item["start"], not item["leak"]))
    return marks[:limit]


def _expand(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    allowed = set(DEFAULT_EXTENSIONS)
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            files.extend(sorted(item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in allowed))
        elif path.is_file():
            files.append(path)
        else:
            raise InvestigationError(f"Nicht gefunden: {raw}")
    unique: dict[str, Path] = {}
    for path in files:
        unique.setdefault(str(path.resolve()), path)
    return list(unique.values())


def _checkpoint(db) -> None:
    """Fold the write-ahead log back into the index file; it only saves space, so it may fail."""
    try:
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    except sqlite3.Error:
        pass


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


class _Reading:
    """What reading one file found out: counts for its statistics and how its times were judged."""

    def __init__(self) -> None:
        self.source_id = 0
        self.name = ""
        self.path = ""
        self.parser_label = ""
        self.replaces: list[int] = []
        self.contexts: dict[str, int] = {}
        self.lines = 0
        self.events = 0
        self.digest: str | None = None
        self.detected: int | None = None
        self.default: tuple[int | None, str] = (None, "local")
        self.bases: set[tuple] = set()  # the zones lines without one were given while reading
        self.stated: set[int] = set()
        self.etypes: dict[str, int] = {}
        self.flags: dict[str, int] = {}
        self.bins: dict[tuple[int, int], int] = {}
        self.first_ms: int | None = None
        self.last_ms: int | None = None

    def stamp(self, wall_ms: int | None, line_off: int | None, raw_flag: str, detected: int | None):
        """Offset, flag and UTC time with what is known while reading; corrected at the end if need be."""
        if wall_ms is None:
            return None, "invalid" if raw_flag == "invalid" else "none", None
        if raw_flag == "exact" and line_off is not None:
            self.stated.add(line_off)
            return line_off, "exact", wall_ms - line_off * 60000
        default_offset, default_flag = self.default
        if detected is not None:
            offset, flag = detected, "source"
            self.bases.add(("source", detected))
        elif default_offset is not None:
            offset, flag = default_offset, default_flag
            self.bases.add((default_flag, default_offset))
        else:
            offset, flag = local_offset(wall_ms), "local"
            self.bases.add(("local", None))
        if raw_flag in ("inherited", "ambiguous"):
            flag = raw_flag
        return offset, flag, wall_ms - offset * 60000

    def count(self, etype: str, flag: str, ts: int | None, severity: int) -> None:
        self.events += 1
        self.etypes[etype] = self.etypes.get(etype, 0) + 1
        self.flags[flag] = self.flags.get(flag, 0) + 1
        if ts is not None:
            key = (ts // BIN_MS, severity)
            self.bins[key] = self.bins.get(key, 0) + 1
            if self.first_ms is None or ts < self.first_ms:
                self.first_ms = ts
            if self.last_ms is None or ts > self.last_ms:
                self.last_ms = ts


class _EntityCache:
    """Entity ids by kind and value during an import.

    A new entity gets its id at once and is written with the next batch of
    events. The cache is bounded; what falls out is looked up again.
    """

    LIMIT = 300_000

    def __init__(self, db) -> None:
        self.db = db
        self.ids: dict[tuple[str, str], int] = {}
        self.pending: list[tuple] = []
        self.next_id = (db.execute("SELECT MAX(id) FROM entities").fetchone()[0] or 0) + 1

    def id_for(self, kind: str, value: str, display: str = "") -> int:
        key = (kind, value)
        known = self.ids.get(key)
        if known is not None:
            return known
        row = self.db.execute("SELECT id FROM entities WHERE kind = ? AND value = ?", key).fetchone()
        if row is not None:
            known = row[0]
        else:
            known = self.next_id
            self.next_id += 1
            generic = 1 if entities.is_generic(kind, value) else 0
            self.pending.append((known, kind, value, (display or value)[:300], generic))
        if len(self.ids) >= self.LIMIT:
            self.flush()
            self.ids.clear()
        self.ids[key] = known
        return known

    def flush(self) -> None:
        if self.pending:
            self.db.executemany(
                "INSERT INTO entities(id, kind, value, display, generic) VALUES (?, ?, ?, ?, ?)", self.pending
            )
            self.pending.clear()

    def forget_pending(self) -> None:
        """After a rollback: entities not committed are gone, and so are their ids."""
        self.pending.clear()
        self.ids.clear()
        self.next_id = (self.db.execute("SELECT MAX(id) FROM entities").fetchone()[0] or 0) + 1


class _Job:
    """One file of an import."""

    def __init__(self, path: Path, phase: str) -> None:
        self.path = path
        self.phase = phase
        self.size = _size(path)
        self.digest: str | None = None  # known before reading when another file has the same size
        self.replaces: list[int] = []  # imported earlier copies of the same growing log


# A growing log copied twice: the later copy begins with all of the earlier one.
# Files are grouped by their first KEY_BYTES; within a group the first
# HEAD_BYTES, and the HEAD_BYTES before the end of the shorter file, sort out
# the rest, before a checksum over the whole shorter file decides.
KEY_BYTES = 512
HEAD_BYTES = 64 * 1024


def _start_key(path: Path) -> str | None:
    """A checksum of the first KEY_BYTES, the same for every copy of a growing log; None for shorter files."""
    try:
        with open(path, "rb") as handle:
            start = handle.read(KEY_BYTES)
    except OSError:
        return None
    return hashlib.sha256(start).hexdigest() if len(start) == KEY_BYTES else None


def _read_at(path: Path, offset: int, size: int) -> bytes:
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read(size)


class _Copy:
    """A file, as far as telling an earlier copy of a growing log from a later one needs it.

    owner is the job or scan entry of a file to import, source the number of
    an imported one. path is None for an imported file that has changed since:
    its checksum then stands for what was read.
    """

    def __init__(self, name: str, size: int, key: str | None, path: Path | None, digest: str | None = None,
                 owner=None, source: int | None = None, place: str = "") -> None:
        self.name = name
        self.place = place or str(path or "")
        self.size = size
        self.key = key
        self.path = path
        self.digest = digest
        self.owner = owner
        self.source = source
        self._head: bytes | None = None
        self._hasher = None
        self._hashed = 0

    def head(self) -> bytes | None:
        if self.path is not None and self._head is None:
            self._head = _read_at(self.path, 0, HEAD_BYTES)
        return self._head

    def full_digest(self) -> str | None:
        if self.digest is None and self.path is not None:
            self.digest = _sha256(self.path)
            if isinstance(self.owner, _Job):
                self.owner.digest = self.digest
        return self.digest

    def prefix_digest(self, size: int) -> str:
        """The checksum of the first size bytes, read on from where the call before stopped."""
        if self._hasher is None or size < self._hashed:
            self._hasher, self._hashed = hashlib.sha256(), 0
        with open(self.path, "rb") as handle:
            handle.seek(self._hashed)
            while self._hashed < size:
                block = handle.read(min(1 << 20, size - self._hashed))
                if not block:
                    break
                self._hasher.update(block)
                self._hashed += len(block)
        return self._hasher.hexdigest()


def _starts_with(longer: _Copy, shorter: _Copy, verify: bool) -> bool:
    """Whether longer begins with all of shorter; without verify, judged from samples of both."""
    if longer.path is None or longer.size <= shorter.size:
        return False
    head = shorter.head()
    if head is not None:
        if longer.head()[:len(head)] != head:
            return False
        if shorter.size <= HEAD_BYTES:
            return True  # all of the shorter one is compared
        if not verify:
            offset = shorter.size - HEAD_BYTES
            return _read_at(longer.path, offset, HEAD_BYTES) == _read_at(shorter.path, offset, HEAD_BYTES)
    elif not verify:
        return True  # an imported file changed since: the same start, the checksum decides at import
    digest = shorter.full_digest()
    return digest is not None and longer.prefix_digest(shorter.size) == digest


def _continued(copies: list[_Copy], verify: bool) -> dict[_Copy, _Copy]:
    """For each copy that a longer one begins with, the longest such copy.

    Pairs of files imported before stay as they are; only pairs with a file
    to import count.
    """
    groups: dict[str, list[_Copy]] = {}
    for copy in copies:
        if copy.key is not None:
            groups.setdefault(copy.key, []).append(copy)
    within: dict[_Copy, _Copy] = {}
    for group in groups.values():
        if len(group) < 2 or all(copy.owner is None for copy in group):
            continue
        group.sort(key=lambda copy: copy.size)
        for index, shorter in enumerate(group):
            for longer in reversed(group[index + 1:]):
                if shorter.owner is None and longer.owner is None:
                    continue
                try:
                    if _starts_with(longer, shorter, verify):
                        within[shorter] = longer
                        break
                except OSError:
                    continue
    return within


def _label(copy: _Copy, other: _Copy) -> str:
    """The name of a copy, with its folder when the other copy has the same name."""
    return f"{PurePath(copy.place).parent.name}/{copy.name}" if copy.name == other.name and copy.place else copy.name


def _longest(within: dict[_Copy, _Copy], copy: _Copy) -> _Copy:
    """The end of a chain of ever longer copies."""
    seen = set()
    while copy in within and copy not in seen:
        seen.add(copy)
        copy = within[copy]
    return copy


def _known_copies(db, copies: list[_Copy]) -> list[_Copy]:
    """The imported files next to the files to import, readable where unchanged since."""
    known = []
    paths = {str(copy.path): copy.key for copy in copies}
    for row in db.execute(
        "SELECT id, name, path, size, mtime_ns, sha256, head FROM sources WHERE state = 'ready' AND size >= ?",
        (KEY_BYTES,),
    ).fetchall():
        path = Path(row[2])
        try:
            stat = path.stat()
            unchanged = stat.st_size == row[3] and stat.st_mtime_ns == row[4]
        except OSError:
            unchanged = False
        key = row[6]
        if key is None and unchanged:
            key = _start_key(path)
            if key is not None:
                db.execute("UPDATE sources SET head = ? WHERE id = ?", (key, row[0]))
        if key is None:
            # Imported by an earlier version and changed since: a file at the same path may continue it.
            key = paths.get(row[2])
        known.append(_Copy(row[1], row[3], key, path if unchanged else None, row[5], source=row[0], place=row[2]))
    return known


def _open_format(path: Path):
    """Encoding and format of a file, judged from its first lines."""
    encoding = logformats.detect_encoding(path)
    sample = [line for _, line in zip(range(300), logformats.read_lines(path, encoding))]
    return encoding, logformats.detect(sample)


def _event_records(path: Path, encoding: str, fmt, info: dict, step, cancelled, hashed: bool):
    """The events of one file as plain values, with all that depends on the file alone.

    Runs in the importing process or in a helper process, with the same
    result. info receives the line count, where every MARK_EVERY-th line
    starts, the checksum when asked for and the zone the file states.
    """
    info.update(path=str(path), lines=0, marks=[], digest=None, detected=None)
    marks = info["marks"]
    hasher = hashlib.sha256() if hashed else None

    def lines():
        if logformats.binary_lines(encoding):
            with open(path, "rb") as handle:
                raw_lines = logformats.read_raw_lines(handle, hasher=hasher, bom=logformats.bom_of(encoding))
                for number, (offset, raw) in enumerate(raw_lines, 1):
                    if number % MARK_EVERY == 1:
                        marks.append((number, offset))
                    info["lines"] = number
                    if number % 5000 == 0:
                        step(offset)
                        if cancelled is not None and cancelled():
                            raise ImportCancelled("Import abgebrochen.")
                    yield raw.decode(encoding, "replace")
        else:
            if hasher is not None:
                info["digest"] = _sha256(path)
            position = 0
            for number, line in enumerate(logformats.read_lines(path, encoding), 1):
                info["lines"] = number
                position += len(line) * 2 + 4
                if number % 5000 == 0:
                    step(position)
                    if cancelled is not None and cancelled():
                        raise ImportCancelled("Import abgebrochen.")
                yield line

    hints = logformats.Hints(path.name, date_from_name(path.name))
    for event in fmt.parse(lines(), hints):
        # What the format read from known positions comes first and brings its role.
        first: dict[tuple, entities.Found] = {}
        roles: dict[tuple, str] = {}
        for found in [*event.ids, *entities.extract(event.text)]:
            key = (found.kind, found.value)
            first.setdefault(key, found)
            if found.role and not roles.get(key):
                roles[key] = found.role
        # "to 192.0.2.10:993" is the server's endpoint when the address is the server's.
        for key in first:
            if key[0] == "endpoint" and not roles.get(key):
                address = key[1].rsplit(":", 1)[0].strip("[]")
                roles[key] = roles.get(("ipv4", address)) or roles.get(("ipv6", address)) or ""
        yield (
            event.line_start, event.line_end, to_ms(event.wall) if event.wall else None, event.offset,
            event.ts_flag, event.etype, event.severity, event.context, event.context_kind, event.context_label,
            event.text, [(kind, value, found.display, roles.get((kind, value), "")) for (kind, value), found in first.items()],
            getattr(fmt, "detected_offset", None),
        )
    info["detected"] = getattr(fmt, "detected_offset", None)
    if hasher is not None and info["digest"] is None:
        info["digest"] = hasher.hexdigest()


# Imports from this size on are parsed in helper processes; below, starting them takes longer than it saves.
PARALLEL_MIN_BYTES = 32 * 1024 * 1024
# More helpers than this outrun the one process writing the index.
READERS_MAX = 3
READER_PORTION = 1000


def _reader_count(size: int, files: int) -> int:
    """Helper processes for an import: LOGMASQUE_IMPORT_READERS sets the number, 0 turns them off."""
    configured = os.environ.get("LOGMASQUE_IMPORT_READERS", "").strip()
    if configured.isdigit():
        count = min(int(configured), 16)
    elif size < PARALLEL_MIN_BYTES:
        return 0
    else:
        count = min(READERS_MAX, (os.cpu_count() or 1) - 1)
    return max(0, min(count, files))


def _reader(tasks, channel, stop) -> None:
    """A helper process of the import: parses the files it takes and hands over their events.

    Everything goes through its own pipe, sent from this thread: a message is
    always complete before the helper can end, and a helper that dies leaves
    the importing process an end of file instead of half a message.
    """
    with contextlib.suppress(ValueError, OSError, AttributeError):
        signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ctrl+C is for the importing process to handle
    try:
        while not stop.is_set():
            task = tasks.get()
            if task is None:
                break
            index, name, hashed = task
            path = Path(name)
            position = [0]

            def step(offset: int) -> None:
                position[0] = offset

            try:
                encoding, fmt = _open_format(path)
                channel.send(("start", index, encoding, fmt.name, fmt.label))
                info: dict = {}
                portion: list[tuple] = []
                for record in _event_records(path, encoding, fmt, info, step, stop.is_set, hashed):
                    portion.append(record)
                    if len(portion) >= READER_PORTION:
                        channel.send(("events", index, portion, position[0]))
                        portion = []
                channel.send(("events", index, portion, position[0]))
                channel.send(("done", index, info))
            except ImportCancelled:
                break
            except (BrokenPipeError, EOFError):
                break  # the importing process stopped listening
            except Exception as error:  # this file fails, the others go on
                channel.send(("error", index, str(error) or type(error).__name__))
    except (BrokenPipeError, EOFError, OSError):
        pass
    finally:
        channel.close()


class _ReadersLost(InvestigationError):
    pass


class _Readers:
    """Helper processes that read and parse files for the import, each one file at a time.

    Each helper sends over a pipe of its own and waits there until its last
    portion is taken; that bounds how far ahead it runs, and the memory.
    """

    def __init__(self, tasks: list[tuple], count: int) -> None:
        context = multiprocessing.get_context("spawn")
        self.tasks = context.Queue()
        self.stop = context.Event()
        self.processes: list = []
        self.channels: list = []
        self.turn = 0
        for task in tasks:
            self.tasks.put(task)
        for _ in range(count):
            self.tasks.put(None)
        try:
            for _ in range(count):
                receiver, sender = context.Pipe(duplex=False)
                process = context.Process(target=_reader, args=(self.tasks, sender, self.stop), daemon=True)
                process.start()
                # Only the helper writes: when it ends, its pipe ends.
                sender.close()
                self.processes.append(process)
                self.channels.append(receiver)
        except BaseException:
            self.close()
            raise

    def _receive(self, timeout: float):
        """The next message of any helper, in turns; None when none came in time."""
        waiting = [channel for channel in self.channels if not channel.closed]
        if not waiting:
            time.sleep(timeout)
            return None
        self.turn = (self.turn + 1) % len(waiting)
        ready = multiprocessing.connection.wait(waiting[self.turn:] + waiting[:self.turn], timeout)
        for channel in ready:
            try:
                return channel.recv()
            except (EOFError, OSError):
                channel.close()  # the helper has ended
        return None

    def next(self, timeout: float = 0.5):
        return self._receive(timeout)

    def lost(self) -> bool:
        """Nothing came: a helper died, or all have ended with files left."""
        if any(process.exitcode not in (None, 0) for process in self.processes):
            return True
        return all(channel.closed for channel in self.channels)

    def close(self) -> None:
        self.stop.set()
        deadline = time.monotonic() + 5
        while any(process.is_alive() for process in self.processes) and time.monotonic() < deadline:
            # A helper waiting to hand over a portion notices the stop once it is taken.
            self._receive(0.05)
        for process in self.processes:
            if process.is_alive():
                process.terminate()
            process.join(2)
        for channel in self.channels:
            channel.close()
        self.tasks.cancel_join_thread()
        self.tasks.close()


class _Writer:
    """Writes the events of the files being imported; event and context numbers are handed out here.

    Events of several files may come in turns; those of one file come in the
    order of its lines and keep it in their numbers.
    """

    PORTION = 2000

    def __init__(self, db, cache: "_EntityCache", committed) -> None:
        self.db = db
        self.cache = cache
        self.committed = committed
        self.next_event = (db.execute("SELECT MAX(id) FROM events").fetchone()[0] or 0) + 1
        self.next_context = (db.execute("SELECT MAX(id) FROM contexts").fetchone()[0] or 0) + 1
        self.event_rows: list[tuple] = []
        self.occurrence_rows: list[tuple] = []
        self.context_rows: list[tuple[int, str]] = []
        self.text_rows: list[tuple[int, str]] = []
        self.uncommitted = 0

    def add(self, reading: "_Reading", record: tuple) -> None:
        (line_start, line_end, wall_ms, line_off, raw_flag, etype, severity, context, context_kind, context_label,
         text, found, detected) = record
        event_id = self.next_event
        self.next_event += 1
        offset, flag, ts = reading.stamp(wall_ms, line_off, raw_flag, detected)
        context_id = None
        if context:
            context = f"{reading.source_id}:{context}"
            context_id = reading.contexts.get(context)
            if context_id is None:
                context_id = reading.contexts[context] = self.next_context
                self.next_context += 1
                self.context_rows.append((context_id, context))
        self.event_rows.append((
            event_id, reading.source_id, line_start, line_end, wall_ms, line_off, raw_flag, offset, ts, flag,
            etype, severity, context_id, SENTINEL if ts is None else ts,
        ))
        self.text_rows.append((event_id, text))
        reading.count(etype, flag, ts, severity)
        id_for = self.cache.id_for
        for kind, value, display, role in found:
            self.occurrence_rows.append((id_for(kind, value, display), event_id, role))
        if context_id is not None and context_kind in CONTEXT_KINDS:
            label = f"{context_label} · {reading.name}"
            self.occurrence_rows.append((id_for(context_kind, context, label), event_id, "context"))
        if len(self.event_rows) >= self.PORTION:
            self.flush()
            if self.uncommitted >= COMMIT_EVERY:
                self.commit()

    def flush(self) -> None:
        self.uncommitted += len(self.event_rows)
        if self.context_rows:
            self.db.executemany("INSERT INTO contexts VALUES (?, ?)", self.context_rows)
            self.context_rows.clear()
        Investigation._flush(self.db, self.cache, self.event_rows, self.occurrence_rows, self.text_rows)

    def commit(self) -> None:
        self.db.commit()
        self.uncommitted = 0
        self.committed()

    def discard(self) -> None:
        """Before a rollback: what is not written yet goes as well."""
        self.event_rows.clear()
        self.occurrence_rows.clear()
        self.context_rows.clear()
        self.text_rows.clear()
        self.uncommitted = 0


def _pack(texts: dict[int, str]) -> bytes:
    """A text block: per event its place in the block, the length and the text, compressed."""
    parts = []
    for slot in sorted(texts):
        data = texts[slot].encode("utf-8", "surrogatepass")
        parts.append(struct.pack("<HI", slot, len(data)))
        parts.append(data)
    return zlib.compress(b"".join(parts), 6)


@functools.lru_cache(maxsize=64)
def _unpack(data: bytes) -> dict[int, str]:
    raw = zlib.decompress(data)
    texts: dict[int, str] = {}
    position = 0
    while position < len(raw):
        slot, length = struct.unpack_from("<HI", raw, position)
        position += 6
        texts[slot] = raw[position:position + length].decode("utf-8", "surrogatepass")
        position += length
    return texts


def _event_text(event_id: int, data: bytes | None) -> str:
    """The text of an event from its block; the SQL function event_text."""
    if data is None:
        return ""
    try:
        return _unpack(bytes(data)).get(event_id & (TEXT_BLOCK - 1), "")
    except (zlib.error, struct.error, UnicodeError):
        return ""


def _store_texts(db, text_rows: list[tuple[int, str]]) -> None:
    """Add texts to their blocks; a block begun by the portion before is completed."""
    blocks: dict[int, dict[int, str]] = {}
    for event_id, text in text_rows:
        blocks.setdefault(event_id >> TEXT_SHIFT, {})[event_id & (TEXT_BLOCK - 1)] = text
    if not blocks:
        return
    for block, data in db.execute(
        f"SELECT block, data FROM texts WHERE block IN ({','.join('?' * len(blocks))})", list(blocks)
    ).fetchall():
        blocks[block] = {**_unpack(bytes(data)), **blocks[block]}
    db.executemany("INSERT OR REPLACE INTO texts VALUES (?, ?)", [(block, _pack(texts)) for block, texts in blocks.items()])


def _drop_texts(db, source_id: int) -> None:
    """The texts of a file's events; blocks shared with another file keep that file's texts."""
    blocks = [row[0] for row in db.execute(
        f"SELECT DISTINCT id >> {TEXT_SHIFT} FROM events WHERE source_id = ?", (source_id,)
    ).fetchall()]
    for start in range(0, len(blocks), 500):
        chunk = blocks[start:start + 500]
        shared = {row[0] for row in db.execute(
            f"SELECT DISTINCT id >> {TEXT_SHIFT} FROM events WHERE source_id != ? AND id >= ? AND id < ? "
            f"AND (id >> {TEXT_SHIFT}) IN ({','.join('?' * len(chunk))})",
            (source_id, min(chunk) << TEXT_SHIFT, (max(chunk) + 1) << TEXT_SHIFT, *chunk),
        )}
        db.executemany("DELETE FROM texts WHERE block = ?", [(block,) for block in chunk if block not in shared])
        for block in shared:
            row = db.execute("SELECT data FROM texts WHERE block = ?", (block,)).fetchone()
            if row is None:
                continue
            keep = {item[0] & (TEXT_BLOCK - 1) for item in db.execute(
                "SELECT id FROM events WHERE id >= ? AND id < ? AND source_id != ?",
                (block << TEXT_SHIFT, (block + 1) << TEXT_SHIFT, source_id),
            )}
            texts = {slot: text for slot, text in _unpack(bytes(row[0])).items() if slot in keep}
            db.execute("UPDATE texts SET data = ? WHERE block = ?", (_pack(texts), block))


PEEK_BYTES = 64 * 1024


def peek_file(path: Path) -> dict:
    """Format, encoding and first and last time of a log file, from its head and tail only."""
    stat = path.stat()
    with open(path, "rb") as handle:
        head = handle.read(PEEK_BYTES)
        tail = b""
        if stat.st_size > PEEK_BYTES:
            handle.seek(max(PEEK_BYTES, stat.st_size - PEEK_BYTES))
            tail = handle.read(PEEK_BYTES)
    encoding = logformats.encoding_of(head)
    head_lines = head.decode(encoding, "replace").splitlines()
    if stat.st_size > PEEK_BYTES and head_lines:
        head_lines = head_lines[:-1]  # cut off in the middle
    fmt = logformats.detect(head_lines[:300])
    hints = logformats.Hints(path.name, date_from_name(path.name))
    first = next((event.wall for event in fmt.parse(head_lines, hints) if event.wall), None)
    if tail:
        tail_lines = tail.decode(encoding, "replace").splitlines()[1:]
        walls = [event.wall for event in type(fmt)().parse(tail_lines, hints) if event.wall]
    else:
        walls = [event.wall for event in type(fmt)().parse(head_lines, hints) if event.wall]
    last = walls[-1] if walls else None
    day = date_from_name(path.name)
    return {
        "path": str(path), "name": path.name, "size": stat.st_size, "mtimeNs": stat.st_mtime_ns,
        "kind": source_kind(path.name), "day": day.isoformat() if day else None,
        "format": fmt.name, "formatLabel": fmt.label, "encoding": encoding,
        "first": first.strftime("%Y-%m-%d %H:%M:%S") if first else None,
        "last": last.strftime("%Y-%m-%d %H:%M:%S") if last else None,
        "firstMs": to_ms(first) if first else None, "lastMs": to_ms(last) if last else None,
        "key": hashlib.sha256(head[:KEY_BYTES]).hexdigest() if len(head) >= KEY_BYTES else None,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _near(sorted_times: list[int], value: int, window: int) -> bool:
    index = bisect.bisect_left(sorted_times, value)
    for neighbour in (index - 1, index):
        if 0 <= neighbour < len(sorted_times) and abs(sorted_times[neighbour] - value) <= window:
            return True
    return False


def _zone(offset_min: int | None) -> str:
    if offset_min is None:
        return ""
    sign = "+" if offset_min >= 0 else "-"
    return f" {sign}{abs(offset_min) // 60:02d}:{abs(offset_min) % 60:02d}"


def _like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


_TOKEN = re.compile(r"[^\W_]+")


def _fts_query(text: str, positions: bool = True) -> tuple[str, list[str]]:
    """The text index query - every word must occur, a trailing * searches by prefix - and the
    words that must also be checked as text.

    With token positions a word of several tokens ("198.51.100.20") is a
    phrase. Without them every token must occur and the word itself is then
    looked for in the matching events.
    """
    terms: list[str] = []
    exact: list[str] = []
    for word in re.findall(r"\S+", text):
        prefix = word.endswith("*") and len(word) > 1
        word = word.rstrip("*")
        if not word:
            continue
        if positions:
            terms.append('"' + word.replace('"', '""') + '"' + ("*" if prefix else ""))
            continue
        tokens = _TOKEN.findall(word)
        if not tokens:
            continue
        terms.extend(f'"{token}"' + ("*" if prefix and index == len(tokens) - 1 else "") for index, token in enumerate(tokens))
        if word != tokens[0]:
            exact.append(word)
    return " AND ".join(terms) or '""', exact


def _normalized_candidates(text: str) -> list[str]:
    text = text.strip()
    if not text:
        return []
    candidates = {text, text.lower(), text.strip("<>").strip(), text.lower().strip("<>[]")}
    normalized = entities.normalize_ip(text)
    if normalized:
        candidates.add(normalized[1])
    if re.fullmatch(r"(?i)(?:md|pd)\d{8,}\.(?:msg|raw)", text.replace("\\", "/").rsplit("/", 1)[-1]):
        candidates.add(text.replace("\\", "/").rsplit("/", 1)[-1].lower())
    return sorted(item for item in candidates if item)


def _entity_dict(row) -> dict:
    return {
        "id": row["id"], "kind": row["kind"], "kindLabel": KIND_LABELS.get(row["kind"], row["kind"]),
        "value": row["value"], "display": row["display"] or row["value"],
        "events": row["events"], "groups": row["groups"], "sources": row["sources"],
        "first": format_ms(row["first_ms"]), "last": format_ms(row["last_ms"]),
        "common": bool(row["common"]), "generic": bool(row["generic"]),
        "weak": row["kind"] in WEAK_KINDS, "unique": row["kind"] in UNIQUE_KINDS,
    }


def dumps(data) -> str:
    return json.dumps(data, ensure_ascii=False)
