"""Local web server that hosts the user interface for both tools.

The interface runs in the browser but the server is strictly local: it binds to
the loopback address, hands out a random session token that every API call has
to repeat in a header, and refuses requests that arrive with a foreign Host
header. Nothing is uploaded anywhere - the browser is only the window, all file
access happens in this process on this machine.
"""

from __future__ import annotations

import copy
import json
import mimetypes
import os
import re
import secrets
import string
import subprocess
import sys
import threading
import time
import traceback
import uuid
import webbrowser
from dataclasses import asdict, dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, applog, investigate
from .anonymize import CATEGORY_LABELS, Anonymizer, Cancelled, Options, default_output_path
from .collect import collect, find_seven_zip, scan
from .lognames import DEFAULT_EXTENSIONS
from .mapping import Mapping
from .store import (
    PasswordRequired,
    StoreError,
    backup_store,
    check_store,
    default_store_path,
    describe_store,
    export_portable,
    import_portable,
    load_mapping,
    save_mapping,
    store_needs_password,
)
from .crypto import dpapi_available

WEB_ROOT = Path(__file__).parent / "web"
# The single-file build (LogMasque.py) carries the interface itself and fills
# this in; the package on disk leaves it empty and serves from WEB_ROOT.
EMBEDDED_WEB: dict[str, str] = {}
MAX_BODY = 8 * 1024 * 1024


@dataclass
class Job:
    id: str
    kind: str
    status: str = "running"
    progress: float = 0.0
    message: str = ""
    result: dict = field(default_factory=dict)
    error: str = ""
    cancel: bool = False
    # What a long run reports while it runs, such as the phase of an import.
    detail: dict = field(default_factory=dict)

    def snapshot(self) -> dict:
        data = asdict(self)
        data.pop("cancel", None)
        return data


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(self, kind: str, worker) -> Job:
        job = Job(id=uuid.uuid4().hex, kind=kind)
        with self._lock:
            self._jobs[job.id] = job

        def run() -> None:
            log = applog.get()
            log.info("job %s (%s) started", job.id[:8], kind)
            started = time.monotonic()
            try:
                job.result = worker(job) or {}
                job.status = "done" if not job.cancel else "cancelled"
                job.progress = 1.0
                log.info("job %s (%s) %s after %.1fs", job.id[:8], kind, job.status, time.monotonic() - started)
            except Cancelled as error:
                job.status = "cancelled"
                job.error = str(error)
                log.warning("job %s (%s) cancelled: %s", job.id[:8], kind, error)
            except Exception as error:  # surfaced in the UI, not swallowed
                job.status = "error"
                job.error = str(error) or error.__class__.__name__
                job.result = {"traceback": traceback.format_exc(limit=3)}
                log.error("job %s (%s) failed: %s\n%s", job.id[:8], kind, error, traceback.format_exc())

        threading.Thread(target=run, name=f"job-{kind}", daemon=True).start()
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None or job.status != "running":
            return False
        job.cancel = True
        job.message = "Cancelling ..."
        return True


class AppState:
    def __init__(self) -> None:
        self.jobs = JobManager()
        self.store_path = str(default_store_path())
        self.store_password: str | None = None
        self.log_path = ""
        # Last scan result, reused by a collect over the same sources.
        self.inventory_key: tuple | None = None
        self.inventory = None
        self.selections: dict[str, list[tuple[str, str]]] = {}
        self.investigation: investigate.Investigation | None = None
        # One object per open investigation, shared by requests and imports,
        # and the import job running for it, if any.
        self.investigations: dict[str, investigate.Investigation] = {}
        self.inv_jobs: dict[str, str] = {}


def _options_from(payload: dict) -> Options:
    return Options(
        mode=str(payload.get("mode", "pseudonym")),
        keep_private_ip=bool(payload.get("keepPrivateIp", False)),
        anonymize_hostname=bool(payload.get("anonymizeHostname", True)),
        keep_domains=tuple(payload.get("keepDomains") or ()),
        extra_patterns=tuple(payload.get("extraPatterns") or ()),
        detect_personal=bool(payload.get("detectPersonal", True)),
    )


def _load_mapping(state: AppState, use_store: bool) -> Mapping:
    if use_store:
        return load_mapping(state.store_path, state.store_password)
    # Without the store nothing is remembered, but own terms and the
    # never-replace list are settings, not mappings, and still apply.
    mapping = Mapping()
    try:
        mapping.user_lists_from(load_mapping(state.store_path, state.store_password))
    except Exception:
        pass
    return mapping


def _check_store_writable(state: AppState, use_store: bool, restore: bool, options: Options) -> None:
    """Fail before anything is written when the mapping could not be persisted."""
    if not use_store or restore or options.redact:
        return
    if store_needs_password(state.store_password):
        raise StoreError(
            "Ohne Windows-DPAPI braucht der Zuordnungsstore ein Kennwort. Setze es über "
            "'Kennwort setzen' in der Store-Karte, sonst ginge die Zuordnung nach dem Lauf verloren."
        )


class Api:
    """Every handler takes the parsed request body and returns a JSON-able dict."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    # -- general ----------------------------------------------------------

    def state_info(self, payload: dict) -> dict:
        info = describe_store(self.state.store_path, self.state.store_password)
        return {
            "version": __version__,
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "cwd": os.getcwd(),
            "home": str(Path.home()),
            "store": asdict(info),
            "sevenZip": find_seven_zip(),
            "dpapi": dpapi_available(),
            "logPath": self.state.log_path,
            "extensions": list(DEFAULT_EXTENSIONS),
            "categories": CATEGORY_LABELS,
            "nativeDialogs": _tkinter_available(),
        }

    def roots(self, payload: dict) -> dict:
        places = []
        home = Path.home()
        for label, path in (
            ("Home", home),
            ("Desktop", home / "Desktop"),
            ("Downloads", home / "Downloads"),
            ("Documents", home / "Documents"),
        ):
            if path.is_dir():
                places.append({"label": label, "path": str(path)})
        if sys.platform == "win32":
            for letter in string.ascii_uppercase:
                drive = Path(f"{letter}:\\")
                if drive.exists():
                    places.append({"label": f"{letter}:", "path": str(drive)})
        else:
            places.append({"label": "/", "path": "/"})
        return {"places": places}

    def browse(self, payload: dict) -> dict:
        raw = str(payload.get("path") or Path.home())
        path = Path(raw).expanduser()
        if not path.is_dir():
            path = path.parent if path.parent.is_dir() else Path.home()
        entries = []
        try:
            for item in sorted(path.iterdir(), key=lambda value: (not value.is_dir(), value.name.lower())):
                try:
                    stat = item.stat()
                except OSError:
                    continue
                if item.is_dir():
                    entries.append({"name": item.name, "path": str(item), "kind": "dir"})
                else:
                    suffix = item.suffix.lower()
                    entries.append(
                        {
                            "name": item.name,
                            "path": str(item),
                            "kind": "zip" if suffix == ".zip" else "file",
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        }
                    )
        except PermissionError as error:
            return {"path": str(path), "parent": str(path.parent), "entries": [], "error": str(error)}
        parent = str(path.parent) if path.parent != path else ""
        return {"path": str(path), "parent": parent, "entries": entries}

    def pick(self, payload: dict) -> dict:
        """Open a native dialog in a helper process when tkinter is present."""
        kind = str(payload.get("kind", "dir"))
        if not _tkinter_available():
            return {"supported": False, "paths": []}
        script = (
            "import tkinter, json, sys\n"
            "from tkinter import filedialog\n"
            "root = tkinter.Tk(); root.withdraw(); root.attributes('-topmost', True)\n"
            "kind = sys.argv[1]\n"
            "if kind == 'dir':\n"
            "    result = [filedialog.askdirectory()]\n"
            "elif kind == 'save':\n"
            "    result = [filedialog.asksaveasfilename()]\n"
            "else:\n"
            "    result = list(filedialog.askopenfilenames())\n"
            "print(json.dumps([item for item in result if item]))\n"
        )
        try:
            completed = subprocess.run(
                [sys.executable, "-c", script, kind], capture_output=True, text=True, timeout=300
            )
            paths = json.loads(completed.stdout.strip() or "[]")
        except Exception:
            return {"supported": False, "paths": []}
        return {"supported": True, "paths": paths}

    def echo(self, payload: dict) -> dict:
        """Reports back how many bytes arrived, to measure the usable request size."""
        size = len(str(payload.get("pad", "")))
        applog.get().info("echo: %d bytes of payload arrived", size)
        return {"size": size}

    def selection_add(self, payload: dict) -> dict:
        """Collect the chosen cells in small pieces before the job is started.

        Some machines drop larger local POST bodies somewhere between browser
        and server, so the selection travels in chunks that stay small.
        """
        selection_id = str(payload.get("id", ""))
        if not selection_id:
            raise ValueError("A selection id is required.")
        if payload.get("reset"):
            self.state.selections[selection_id] = []
        bucket = self.state.selections.setdefault(selection_id, [])
        for item in payload.get("pairs") or []:
            if len(item) == 2:
                bucket.append((str(item[0]), str(item[1])))
        # Only a handful of selections are ever in flight; drop the oldest.
        while len(self.state.selections) > 8:
            self.state.selections.pop(next(iter(self.state.selections)))
        return {"count": len(bucket)}

    def client_log(self, payload: dict) -> dict:
        """Entries the interface could not resolve itself, so the log has both sides."""
        level = str(payload.get("level", "info"))
        message = str(payload.get("message", ""))[:500]
        context = str(payload.get("context", ""))[:200]
        line = f"ui [{context}] {message}" if context else f"ui {message}"
        applog.get().warning(line) if level == "error" else applog.get().info(line)
        return {"logged": True}

    def job(self, payload: dict) -> dict:
        job = self.state.jobs.get(str(payload.get("id", "")))
        if job is None:
            raise KeyError("Unknown job.")
        return job.snapshot()

    def cancel(self, payload: dict) -> dict:
        return {"cancelled": self.state.jobs.cancel(str(payload.get("id", "")))}

    # -- collect ----------------------------------------------------------

    def scan(self, payload: dict) -> dict:
        sources = list(payload.get("sources") or [])
        if not sources:
            raise ValueError("Add at least one source first.")
        extensions = payload.get("extensions") or None
        fallback = bool(payload.get("containerFallback", False))

        def worker(job: Job) -> dict:
            def progress(value: float) -> None:
                job.progress = value
                job.message = "Quellen werden gelesen ..."

            applog.get().info("scan of %d source(s): %s", len(sources), "; ".join(sources))
            inventory = scan(
                sources,
                extensions=extensions,
                use_container_date_fallback=fallback,
                progress=progress,
                cancelled=lambda: job.cancel,
            )
            self.state.inventory_key = (tuple(sources), tuple(extensions or ()), fallback)
            self.state.inventory = inventory
            matrix = inventory.matrix()
            applog.get().info(
                "scan result: %d dated files, %d undated, %d types, %d days, %d archives, %d archive errors",
                matrix["total"], matrix["undated"], len(matrix["types"]), len(matrix["days"]),
                matrix["archivesScanned"], len(matrix["archiveErrors"]),
            )
            for entry in matrix["archiveErrors"]:
                applog.get().warning("archive unreadable: %s (%s)", entry["source"], entry["error"])
            return matrix

        return {"job": self.state.jobs.start("scan", worker).id}

    def collect(self, payload: dict) -> dict:
        sources = list(payload.get("sources") or [])
        days = list(payload.get("days") or [])
        types = list(payload.get("logTypes") or [])
        pairs = [(str(item[0]), str(item[1])) for item in payload.get("pairs") or [] if len(item) == 2]
        selection_id = str(payload.get("selectionId", ""))
        if selection_id:
            pairs = list(self.state.selections.get(selection_id, []))
            if not pairs:
                raise ValueError("The transferred selection was not found; scan and select again.")
        target = str(payload.get("target") or "").strip()
        as_archive = bool(payload.get("asArchive", False))
        if not sources:
            raise ValueError("Add at least one source first.")
        if not target:
            raise ValueError("Choose where the selection should be written.")

        def worker(job: Job) -> dict:
            log = applog.get()
            last_logged = [0.0]

            def progress(value: float, name: str = "") -> None:
                job.progress = value
                job.message = name or ""
                if value - last_logged[0] >= 0.05:
                    last_logged[0] = value
                    log.info("collect %d%% (%s)", round(value * 100), name or "...")

            key = (tuple(sources), tuple(payload.get("extensions") or ()), bool(payload.get("containerFallback", False)))
            prepared = self.state.inventory if self.state.inventory_key == key else None
            log.info(
                "collect: %d pair(s), target %s, %s, inventory %s",
                len(pairs), target, "archive" if as_archive else "folder",
                "reused from the scan" if prepared else "read again",
            )
            result = collect(
                sources,
                days=days,
                log_types=types,
                pairs=pairs,
                inventory=prepared,
                collection_directory=None if as_archive else target,
                output_archive=target if as_archive else None,
                extensions=payload.get("extensions") or None,
                use_container_date_fallback=bool(payload.get("containerFallback", False)),
                force=bool(payload.get("force", False)),
                progress=progress,
                cancelled=lambda: job.cancel,
            )
            return asdict(result)

        return {"job": self.state.jobs.start("collect", worker).id}

    # -- anonymize --------------------------------------------------------

    def preview(self, payload: dict) -> dict:
        """Anonymize a snippet without ever touching the stored mapping."""
        options = _options_from(payload)
        use_store = bool(payload.get("useStore", True))
        restore = bool(payload.get("restore", False))
        text = str(payload.get("text") or "")
        source = str(payload.get("path") or "")
        limit = int(payload.get("limit", 40))

        if source and not text:
            from .anonymize import resolve_encodings, split_line_ending

            path = Path(source)
            read_encoding, _ = resolve_encodings(path, str(payload.get("encoding", "auto")))
            collected = []
            with path.open("r", encoding=read_encoding, errors="surrogateescape", newline="") as handle:
                for index, raw in enumerate(handle):
                    if index >= limit:
                        break
                    collected.append(split_line_ending(raw)[0])
            text = "\n".join(collected)

        mapping = copy.deepcopy(_load_mapping(self.state, use_store))
        engine = Anonymizer(mapping, options)
        if not restore:
            engine.learn_text(text)
        transform = engine.restore_segments if restore else engine.segments
        lines = []
        for line in text.split("\n")[:limit]:
            lines.append(
                [
                    {"text": segment.text, "category": segment.category, "original": segment.original}
                    for segment in transform(line)
                ]
            )
        return {
            "lines": lines,
            "stats": engine.stats,
            "restored": engine.restored,
            "unresolved": engine.unresolved,
            "unknownTokens": sorted(engine.unknown_tokens),
            "truncated": len(text.split("\n")) > limit,
        }

    def anonymize_text(self, payload: dict) -> dict:
        """Convert pasted text and persist any new mapping entries."""
        options = _options_from(payload)
        use_store = bool(payload.get("useStore", True))
        restore = bool(payload.get("restore", False))
        text = str(payload.get("text") or "")
        _check_store_writable(self.state, use_store, restore, options)
        mapping = _load_mapping(self.state, use_store)
        engine = Anonymizer(mapping, options)
        if not restore:
            engine.learn_text(text)
        transform = engine.restore_line if restore else engine.process_line
        output = "\n".join(transform(line) for line in text.split("\n"))
        backup = None
        if use_store and not restore and options.mode != "redact":
            backup = save_mapping(self.state.store_path, mapping, self.state.store_password)
        return {
            "text": output,
            "stats": engine.stats,
            "restored": engine.restored,
            "unresolved": engine.unresolved,
            "unknownTokens": sorted(engine.unknown_tokens),
            "backup": backup,
        }

    def anonymize_files(self, payload: dict) -> dict:
        files = [str(item) for item in payload.get("files") or []]
        if not files:
            raise ValueError("Add at least one file first.")
        options = _options_from(payload)
        use_store = bool(payload.get("useStore", True))
        restore = bool(payload.get("restore", False))
        output = str(payload.get("output") or "").strip() or None
        encoding = str(payload.get("encoding", "auto"))
        force = bool(payload.get("force", False))
        mapping_csv = str(payload.get("mappingCsv") or "").strip() or None
        _check_store_writable(self.state, use_store, restore, options)

        def worker(job: Job) -> dict:
            mapping = _load_mapping(self.state, use_store)
            engine = Anonymizer(mapping, options)
            if output:
                Path(output).mkdir(parents=True, exist_ok=True)
            processed = []
            for index, source in enumerate(files):
                if job.cancel:
                    raise Cancelled("Cancelled; already written files stay on disk and must be reviewed.")
                source_path = Path(source)
                target = default_output_path(source_path, output, restore)
                if target.exists() and not force:
                    raise FileExistsError(f"Output file already exists: {target}")
                if target.resolve() == source_path.resolve():
                    raise ValueError(f"Source and destination are identical: {source_path}")
                job.message = source_path.name

                def progress(fraction: float, position=index) -> None:
                    job.progress = (position + fraction) / len(files)

                lines = engine.process_file(
                    source_path,
                    target,
                    encoding=encoding,
                    restore=restore,
                    progress=progress,
                    cancelled=lambda: job.cancel,
                )
                processed.append({"source": str(source_path), "target": str(target), "lines": lines})
                job.progress = (index + 1) / len(files)

            backup = None
            if use_store and not restore and options.mode != "redact":
                backup = save_mapping(self.state.store_path, mapping, self.state.store_password)
            if mapping_csv:
                _write_mapping_csv(mapping, mapping_csv)
            return {
                "files": processed,
                "stats": engine.stats,
                "restored": engine.restored,
                "unresolved": engine.unresolved,
                "unknownTokens": sorted(engine.unknown_tokens),
                "backup": backup,
                "mappingCsv": mapping_csv,
            }

        return {"job": self.state.jobs.start("anonymize", worker).id}

    # -- store ------------------------------------------------------------

    def store_info(self, payload: dict) -> dict:
        password = payload.get("password")
        if password:
            self.state.store_password = str(password)
        info = describe_store(self.state.store_path, self.state.store_password)
        # A store that will not open is the failure that matters most, so it
        # belongs in the log even though the UI receives it as plain data.
        if info.exists and not info.readable:
            applog.get().warning("store not readable (%s): %s", info.protection or "unknown", info.message)
        else:
            applog.get().info("store %s, %s entries", info.protection or "empty", info.total)
        return asdict(info)

    # -- own terms, own patterns, never replace ------------------------------

    def lists(self, payload: dict) -> dict:
        mapping = load_mapping(self.state.store_path, self.state.store_password)
        return _lists_of(mapping)

    def lists_change(self, payload: dict) -> dict:
        """Add to or take off one of the lists; the store is written right away."""
        kind = str(payload.get("kind", ""))
        action = str(payload.get("action", "add"))
        value = str(payload.get("value") or "").strip()
        if not value:
            raise ValueError("Bitte einen Begriff angeben.")
        if kind == "term" and len(value) > 2 and value.startswith("/") and value.endswith("/"):
            kind, value = "pattern", value[1:-1]
        if store_needs_password(self.state.store_password):
            raise StoreError("Der Store ist gesperrt. Erst entsperren, dann die Liste ändern.")
        mapping = load_mapping(self.state.store_path, self.state.store_password)
        if kind == "term":
            changed = mapping.add_term(value) if action == "add" else mapping.remove_term(value)
        elif kind == "pattern":
            if action == "add":
                try:
                    mapping.add_pattern(value)
                except re.error as error:
                    raise ValueError(f"Das Muster ist ungültig: {error}") from None
                changed = True
            else:
                changed = mapping.remove_pattern(value)
        elif kind == "ignore":
            changed = mapping.ignore(value) if action == "add" else mapping.unignore(value)
        else:
            raise ValueError(f"Unbekannte Liste: {kind}")
        save_mapping(self.state.store_path, mapping, self.state.store_password)
        applog.get().info("list %s: %s %s", kind, action, "changed" if changed is not False else "unchanged")
        return _lists_of(mapping)

    def store_check(self, payload: dict) -> dict:
        report = check_store(self.state.store_path, self.state.store_password)
        applog.get().info("store check: %s", "; ".join(f"{label}={value}" for label, value in report))
        return {"report": [{"label": label, "value": value} for label, value in report]}

    def store_export(self, payload: dict) -> dict:
        target = str(payload.get("path") or "").strip()
        password = str(payload.get("password") or "")
        if not target:
            raise ValueError("Choose where the backup should be written.")
        export_portable(
            self.state.store_path,
            target,
            password,
            force=bool(payload.get("force", False)),
            store_password=self.state.store_password,
        )
        return {"path": target}

    def store_import(self, payload: dict) -> dict:
        source = str(payload.get("path") or "").strip()
        password = str(payload.get("password") or "")
        if not source:
            raise ValueError("Choose the .anonstore file to import.")
        backup = import_portable(
            source,
            self.state.store_path,
            password,
            force=True,
            store_password=self.state.store_password,
        )
        return {"backup": backup, "store": asdict(describe_store(self.state.store_path, self.state.store_password))}

    def store_reset(self, payload: dict) -> dict:
        path = Path(self.state.store_path)
        if not path.is_file():
            return {"backup": None, "removed": False}
        backup = backup_store(path)
        path.unlink()
        return {"backup": backup, "removed": True}

    def store_rows(self, payload: dict) -> dict:
        mapping = _load_mapping(self.state, True)
        rows = mapping.rows()
        limit = int(payload.get("limit", 500))
        return {
            "rows": [{"category": row[0], "original": row[1], "token": row[2]} for row in rows[:limit]],
            "total": len(rows),
        }

    # -- investigate ------------------------------------------------------

    def _inv_folder(self) -> Path:
        return investigate.investigations_folder(self.state.store_path)

    def _inv(self) -> investigate.Investigation:
        if self.state.investigation is None:
            raise investigate.InvestigationError("Keine Untersuchung geöffnet. Lege eine an oder öffne eine vorhandene.")
        return self.state.investigation

    def _inv_object(self, path: Path) -> investigate.Investigation:
        investigation = self.state.investigations.get(path.stem)
        if investigation is None:
            investigation = self.state.investigations[path.stem] = investigate.Investigation(path)
        return investigation

    def _inv_job(self, investigation_id: str) -> str | None:
        """The import running for an investigation, if any."""
        job_id = self.state.inv_jobs.get(investigation_id)
        job = self.state.jobs.get(job_id) if job_id else None
        if job is None or job.status != "running":
            self.state.inv_jobs.pop(investigation_id, None)
            return None
        return job_id

    def _inv_idle(self, investigation: investigate.Investigation) -> None:
        if self._inv_job(investigation.id):
            raise investigate.InvestigationError(
                "Während des Imports nicht möglich. Bitte warten, bis er fertig ist, oder ihn abbrechen."
            )

    def _inv_overview(self, investigation: investigate.Investigation) -> dict:
        overview = investigation.overview()
        overview["importJob"] = self._inv_job(investigation.id)
        return overview

    def inv_list(self, payload: dict) -> dict:
        current = self.state.investigation
        return {
            "items": investigate.list_investigations(self._inv_folder()),
            "current": current.id if current else None,
            "folder": str(self._inv_folder()),
        }

    def inv_create(self, payload: dict) -> dict:
        created = investigate.create_investigation(self._inv_folder(), str(payload.get("name") or ""))
        self.state.investigation = self.state.investigations[created.id] = created
        applog.get().info("investigation created: %s", created.path)
        return self._inv_overview(created)

    def inv_open(self, payload: dict) -> dict:
        path = investigate.investigation_path(self._inv_folder(), str(payload.get("id") or ""))
        self.state.investigation = self._inv_object(path)
        return self._inv_overview(self.state.investigation)

    def inv_delete(self, payload: dict) -> dict:
        target = str(payload.get("id") or "")
        if self._inv_job(target):
            raise investigate.InvestigationError("Diese Untersuchung importiert gerade. Bitte zuerst den Import abbrechen.")
        if self.state.investigation is not None and self.state.investigation.id == target:
            self.state.investigation = None
        self.state.investigations.pop(target, None)
        investigate.delete_investigation(self._inv_folder(), target)
        applog.get().info("investigation deleted: %s", target)
        return self.inv_list({})

    def inv_overview(self, payload: dict) -> dict:
        return self._inv_overview(self._inv())

    def inv_scan(self, payload: dict) -> dict:
        """Head and tail of every file: log types, sizes and time ranges before anything is indexed."""
        paths = [str(item) for item in payload.get("paths") or [] if str(item).strip()]
        if not paths:
            raise ValueError("Zuerst Dateien oder einen Ordner wählen.")
        investigation = self._inv()

        def worker(job: Job) -> dict:
            def progress(value: float, name: str = "") -> None:
                job.progress = value
                job.message = name

            return {"scan": investigation.scan_paths(paths, progress=progress, cancelled=lambda: job.cancel)}

        return {"job": self.state.jobs.start("scan-logs", worker).id}

    def inv_import(self, payload: dict) -> dict:
        """Priority files first, then the background ones; both lists hold files or folders."""
        priority = [str(item) for item in payload.get("priority") or payload.get("paths") or [] if str(item).strip()]
        background = [str(item) for item in payload.get("background") or [] if str(item).strip()]
        if not priority and not background:
            raise ValueError("Zuerst Dateien oder einen Ordner wählen.")
        investigation = self._inv()
        self._inv_idle(investigation)

        def worker(job: Job) -> dict:
            def progress(value: float, name: str = "") -> None:
                job.progress = value
                job.message = name

            def status(detail: dict) -> None:
                job.detail.update(detail)

            def ready() -> None:
                job.detail["ready"] = True
                applog.get().info("investigation import: priority files ready")

            applog.get().info(
                "investigation import of %d priority and %d background path(s)", len(priority), len(background)
            )
            report = investigation.import_plan(
                priority, background, progress=progress, cancelled=lambda: job.cancel, status=status, ready=ready
            )
            readers = report.get("readers") or {}
            if readers.get("fallback"):
                applog.get().warning("import helpers gave up, read in this process: %s", readers["fallback"])
            elif readers:
                applog.get().info("investigation import with %d helper process(es)", readers["count"])
            if report["continued"] or report["replaced"]:
                applog.get().info(
                    "investigation import: %d earlier copy(ies) left out, %d imported copy(ies) replaced",
                    len(report["continued"]), len(report["replaced"]),
                )
            for failed in report["failed"]:
                applog.get().warning("import failed: %s (%s)", failed["path"], failed["error"])
            return {"report": report, "overview": investigation.overview()}

        job = self.state.jobs.start("investigate", worker)
        self.state.inv_jobs[investigation.id] = job.id
        return {"job": job.id}

    def inv_time(self, payload: dict) -> dict:
        """Recomputing every time can take a while on large investigations, so it runs as a job."""
        investigation = self._inv()
        self._inv_idle(investigation)
        source = payload.get("sourceId")
        offset = payload.get("offset")
        arguments = (
            int(source) if source not in (None, "") else None,
            str(payload.get("mode") or "auto"),
            int(offset) if offset not in (None, "") else None,
            float(payload.get("skewSeconds") or 0),
        )
        if arguments[1] not in ("auto", "local", "fixed"):
            raise investigate.InvestigationError("Unbekannte Zeiteinstellung.")

        def worker(job: Job) -> dict:
            job.message = "Zeiten werden neu berechnet …"
            investigation.set_time(*arguments)
            return {"overview": investigation.overview()}

        job = self.state.jobs.start("investigate-time", worker)
        self.state.inv_jobs[investigation.id] = job.id
        return {"job": job.id}

    def inv_remove_source(self, payload: dict) -> dict:
        investigation = self._inv()
        self._inv_idle(investigation)
        investigation.remove_source(int(payload.get("sourceId")))
        return self._inv_overview(investigation)

    def inv_suggest(self, payload: dict) -> dict:
        return {"items": self._inv().suggest(str(payload.get("query") or ""))}

    def inv_search(self, payload: dict) -> dict:
        def number(key):
            value = payload.get(key)
            return int(value) if value not in (None, "") else None

        return self._inv().search(
            query=str(payload.get("query") or ""),
            entity_ids=[int(item) for item in payload.get("entities") or []],
            sources=[int(item) for item in payload.get("sources") or []],
            etypes=[str(item) for item in payload.get("etypes") or []],
            min_severity=int(payload.get("minSeverity", 1)),
            time_from=number("from"),
            time_to=number("to"),
            levels=[int(item) for item in payload.get("levels") or []] or None,
            temporal_seconds=int(payload.get("temporalSeconds") or 0),
            limit=int(payload.get("limit", 200)),
            offset=int(payload.get("offset", 0)),
            ids_only=bool(payload.get("idsOnly", False)),
        )

    def inv_event(self, payload: dict) -> dict:
        return self._inv().event_detail(
            int(payload.get("id")), anchor_ids=[int(item) for item in payload.get("anchors") or []] or None
        )

    def inv_context(self, payload: dict) -> dict:
        return {"rows": self._inv().context_events(int(payload.get("id")))}

    def inv_entity(self, payload: dict) -> dict:
        return self._inv().entity_detail(int(payload.get("id")))

    def inv_graph(self, payload: dict) -> dict:
        return self._inv().graph(int(payload.get("id")), [str(item) for item in payload.get("kinds") or []] or None)

    def inv_flag(self, payload: dict) -> dict:
        return self._inv().flag_entity(int(payload.get("id")), str(payload.get("action") or "reset"))

    def inv_link(self, payload: dict) -> dict:
        self._inv().exclude_link(int(payload.get("a")), int(payload.get("b")), bool(payload.get("undo", False)))
        return {"ok": True}

    def inv_export(self, payload: dict) -> dict:
        """Masked events for an outside analysis: a preview first, then the release.

        The preview never touches the store. The release uses the same mapping,
        saves new placeholders to the store so they can be restored later, and
        refuses while original values are readable or the review is not confirmed.
        """
        events = [int(item) for item in payload.get("events") or []]
        use_store = bool(payload.get("useStore", True))
        confirm = bool(payload.get("confirm", False))
        investigation = self._inv()
        if confirm:
            _check_store_writable(self.state, use_store, False, Options())
        mapping = _load_mapping(self.state, use_store)
        result = investigation.export_text(events, mapping if confirm else copy.deepcopy(mapping))
        result["reversible"] = use_store
        if not confirm:
            return result
        if result["blocked"]:
            raise ValueError("Export gesperrt: Im Ergebnis stehen noch Originalwerte. Siehe Vorschau.")
        if result["needsReview"] and not payload.get("reviewed"):
            raise ValueError("Bitte zuerst bestätigen, dass die markierten Stellen geprüft wurden.")
        if use_store:
            save_mapping(self.state.store_path, mapping, self.state.store_password)
        applog.get().info("investigation export released: %d events", result["events"])
        return result


def _lists_of(mapping: Mapping) -> dict:
    return {
        "terms": [
            {"value": term, "token": mapping.maps["Extra"].get(mapping.find("Extra", term) or "", "")}
            for term in mapping.terms
        ],
        "patterns": list(mapping.patterns),
        "ignored": sorted(mapping.ignored.values(), key=str.casefold),
    }


def _write_mapping_csv(mapping: Mapping, target: str) -> None:
    import csv

    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Typ", "Original", "Token"])
        writer.writerows(mapping.rows())


def _tkinter_available() -> bool:
    try:
        import tkinter  # noqa: F401
    except Exception:
        return False
    return True


ROUTES = {
    "/api/state": "state_info",
    "/api/roots": "roots",
    "/api/browse": "browse",
    "/api/pick": "pick",
    "/api/job": "job",
    "/api/clientlog": "client_log",
    "/api/echo": "echo",
    "/api/selection": "selection_add",
    "/api/job/cancel": "cancel",
    "/api/scan": "scan",
    "/api/collect": "collect",
    # Same handler under a plainer name: some endpoint filters refuse paths
    # containing words such as "collect", so the client falls back to this one.
    "/api/start": "collect",
    "/api/preview": "preview",
    "/api/anonymize/text": "anonymize_text",
    "/api/anonymize/files": "anonymize_files",
    "/api/store/info": "store_info",
    "/api/store/check": "store_check",
    "/api/store/export": "store_export",
    "/api/store/import": "store_import",
    "/api/store/reset": "store_reset",
    "/api/store/rows": "store_rows",
    "/api/lists": "lists",
    "/api/lists/change": "lists_change",
    "/api/inv/list": "inv_list",
    "/api/inv/create": "inv_create",
    "/api/inv/open": "inv_open",
    "/api/inv/delete": "inv_delete",
    "/api/inv/overview": "inv_overview",
    "/api/inv/import": "inv_import",
    "/api/inv/scan": "inv_scan",
    "/api/inv/time": "inv_time",
    "/api/inv/source/remove": "inv_remove_source",
    "/api/inv/suggest": "inv_suggest",
    "/api/inv/search": "inv_search",
    "/api/inv/event": "inv_event",
    "/api/inv/context": "inv_context",
    "/api/inv/entity": "inv_entity",
    "/api/inv/graph": "inv_graph",
    "/api/inv/flag": "inv_flag",
    "/api/inv/link": "inv_link",
    "/api/inv/export": "inv_export",
}


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    # Status polling opens connections steadily; a roomy backlog keeps a busy
    # moment from turning into a refused connection in the browser.
    request_queue_size = 64
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    server_version = f"logmasque/{__version__}"
    # Keep-alive: one connection carries many polls instead of one each, which
    # avoids hundreds of short-lived loopback connections during a long run.
    protocol_version = "HTTP/1.1"
    token = ""
    api: Api

    def log_message(self, fmt: str, *args) -> None:  # console stays quiet, the file gets it
        applog.get().debug("http %s", fmt % args)

    def log_error(self, fmt: str, *args) -> None:
        applog.get().warning("http %s", fmt % args)

    def handle_one_request(self) -> None:
        # A browser that drops a poll must not look like a server failure.
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError) as error:
            applog.get().info("client connection dropped: %s", error)
            self.close_connection = True

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _local_host(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost", "[::1]", "::1")

    def do_GET(self) -> None:
        if not self._local_host():
            self._send_json(403, {"error": "Only local requests are accepted."})
            return
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._serve_static("index.html")
            return
        if path.startswith("/static/"):
            self._serve_static(path[len("/static/") :])
            return
        self._send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:
        log = applog.get()
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        # Status polling would drown the log; everything else is worth a line,
        # so a request that never reaches its handler is still visible.
        if path != "/api/job":
            log.info("request %s (%d bytes)", path, length)

        # The body is always read, even when the request is rejected: answering
        # without draining it makes Windows reset the connection, which the
        # browser then reports as a bare "Failed to fetch".
        body = b""
        if 0 < length <= MAX_BODY:
            try:
                body = self.rfile.read(length)
            except OSError as error:
                log.warning("%s: body could not be read: %s", path, error)
                return

        if not self._local_host():
            log.warning("%s refused: foreign Host header %r", path, self.headers.get("Host"))
            self._send_json(403, {"error": "Only local requests are accepted."})
            return
        if self.headers.get("X-LogMasque-Token") != self.token:
            log.warning("%s refused: wrong or missing session token", path)
            self._send_json(403, {"error": "Invalid session token. Reopen the interface from the console link."})
            return
        route = ROUTES.get(path)
        if route is None:
            log.warning("%s refused: unknown route", path)
            self._send_json(404, {"error": "Not found."})
            return
        if length > MAX_BODY:
            log.warning("%s refused: body of %d bytes is too large", path, length)
            self._send_json(413, {"error": "Request too large."})
            return
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError as error:
            log.warning("%s refused: invalid JSON: %s", path, error)
            self._send_json(400, {"error": f"Invalid JSON: {error}"})
            return
        log = applog.get()
        started = time.monotonic()
        try:
            data = getattr(self.api, route)(payload)
            log.debug("%s ok in %.0f ms", self.path, (time.monotonic() - started) * 1000)
            self._send_json(200, {"ok": True, "data": data})
        except PasswordRequired as error:
            log.info("%s needs a password", self.path)
            self._send_json(200, {"ok": False, "error": str(error), "needsPassword": True})
        except (StoreError, ValueError, FileNotFoundError, FileExistsError, KeyError, OSError) as error:
            log.warning("%s refused: %s", self.path, error)
            self._send_json(200, {"ok": False, "error": str(error)})
        except Exception as error:
            log.error("%s crashed: %s\n%s", self.path, error, traceback.format_exc())
            self._send_json(200, {"ok": False, "error": f"{error.__class__.__name__}: {error}"})

    def _serve_static(self, relative: str) -> None:
        if EMBEDDED_WEB:
            text = EMBEDDED_WEB.get(relative)
            if text is None:
                self._send_json(404, {"error": "Not found."})
                return
            content = text.encode("utf-8")
        else:
            target = (WEB_ROOT / relative).resolve()
            if not str(target).startswith(str(WEB_ROOT.resolve())) or not target.is_file():
                self._send_json(404, {"error": "Not found."})
                return
            content = target.read_bytes()
        content_type = mimetypes.guess_type(relative)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
            content_type += "; charset=utf-8"
        self._send(200, content, content_type)


def serve(host: str = "127.0.0.1", port: int = 0, open_browser: bool = True, debug: bool = False) -> None:
    log_path = applog.setup(debug=debug)
    log = applog.get()
    state = AppState()
    state.log_path = str(log_path)
    Handler.token = secrets.token_urlsafe(24)
    Handler.api = Api(state)
    httpd = LocalServer((host, port), Handler)
    url = f"http://{host}:{httpd.server_address[1]}/?t={Handler.token}"
    log.info("logmasque %s starting on %s (python %s, %s)", __version__, host, sys.version.split()[0], sys.platform)
    log.info("store: %s", state.store_path)
    print(f"Log tools {__version__} running at {url}")
    print(f"Log file: {log_path}")
    print("Press Ctrl+C to stop. The interface is only reachable from this computer.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        log.info("stopped by the user")
    finally:
        httpd.server_close()
