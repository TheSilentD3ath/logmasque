"""Collecting log files by day and log type from folders, files and ZIP archives.

The date inside the log filename decides, identical files are kept once by
SHA-256, same-named files with different content survive with a numbered
suffix, and a local CSV manifest records where every file came from. Archive
output needs no 7-Zip; a ZIP with LZMA compression is produced with the
standard library.
"""

from __future__ import annotations

import csv
import hashlib
import os
import shutil
import subprocess
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .anonymize import Cancelled
from .lognames import (
    date_from_name,
    log_type_from_name,
    matches_log_type,
    normalize_extensions,
)

MANIFEST_COLUMNS = (
    "Status",
    "Date",
    "LogType",
    "OutputName",
    "OriginalName",
    "SourceKind",
    "SourceName",
    "ArchiveEntry",
    "Bytes",
    "SHA256",
    "Error",
)


@dataclass
class Candidate:
    source_kind: str
    source_path: str
    source_name: str
    entry: str
    name: str
    log_type: str
    day: date | None
    size: int

    @property
    def day_text(self) -> str:
        return self.day.isoformat() if self.day else ""


@dataclass
class Inventory:
    candidates: list[Candidate] = field(default_factory=list)
    archive_errors: list[tuple[str, str]] = field(default_factory=list)
    archives_scanned: int = 0
    files_inspected: int = 0

    def matrix(self) -> dict:
        """Files and bytes per log type and day, for the selection grid in the UI."""
        cells: dict[str, dict[str, list[int]]] = {}
        days: dict[str, int] = {}
        types: dict[str, int] = {}
        undated = 0
        for candidate in self.candidates:
            if not candidate.day:
                undated += 1
                continue
            cell = cells.setdefault(candidate.log_type, {}).setdefault(candidate.day_text, [0, 0])
            cell[0] += 1
            cell[1] += candidate.size
            days[candidate.day_text] = days.get(candidate.day_text, 0) + 1
            types[candidate.log_type] = types.get(candidate.log_type, 0) + 1
        return {
            "days": sorted(days),
            "types": sorted(types, key=str.lower),
            "cells": cells,
            "dayTotals": days,
            "typeTotals": types,
            "undated": undated,
            "total": sum(days.values()),
            "archivesScanned": self.archives_scanned,
            "filesInspected": self.files_inspected,
            "archiveErrors": [{"source": name, "error": message} for name, message in self.archive_errors],
        }


@dataclass
class CollectResult:
    selected: int = 0
    duplicates: int = 0
    archive_errors: int = 0
    archives_scanned: int = 0
    files_inspected: int = 0
    bytes_written: int = 0
    collection_directory: str | None = None
    output_archive: str | None = None
    manifest: str | None = None


def iter_source_files(sources: list[str] | tuple[str, ...]) -> list[Path]:
    """Expand folders and glob patterns into a flat list of files."""
    found: list[Path] = []
    for raw in sources:
        candidate = Path(raw)
        if candidate.is_dir():
            found.extend(sorted(item for item in candidate.rglob("*") if item.is_file()))
        elif candidate.is_file():
            found.append(candidate)
        else:
            parent = candidate.parent if str(candidate.parent) else Path(".")
            found.extend(sorted(item for item in parent.glob(candidate.name) if item.is_file()))
    if not found:
        raise FileNotFoundError("No existing source was found.")
    return found


def scan(
    sources: list[str] | tuple[str, ...],
    extensions=None,
    use_container_date_fallback: bool = False,
    progress=None,
    cancelled=None,
) -> Inventory:
    """List every log file inside the sources without extracting anything."""
    allowed = normalize_extensions(extensions)
    inventory = Inventory()
    files = iter_source_files(sources)
    for index, path in enumerate(files):
        if cancelled is not None and cancelled():
            raise Cancelled("Scan cancelled.")
        if progress is not None:
            progress((index + 1) / len(files))
        if path.suffix.lower() == ".zip":
            inventory.archives_scanned += 1
            container_day = date_from_name(path.name)
            try:
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        if info.is_dir():
                            continue
                        name = Path(info.filename).name
                        if not name:
                            continue
                        inventory.files_inspected += 1
                        if Path(name).suffix.lower() not in allowed:
                            continue
                        day = date_from_name(name)
                        if day is None and use_container_date_fallback:
                            day = container_day
                        inventory.candidates.append(
                            Candidate(
                                source_kind="ZIP",
                                source_path=str(path),
                                source_name=path.name,
                                entry=info.filename,
                                name=name,
                                log_type=log_type_from_name(name),
                                day=day,
                                size=info.file_size,
                            )
                        )
            except (zipfile.BadZipFile, OSError) as error:
                inventory.archive_errors.append((path.name, str(error)))
            continue

        inventory.files_inspected += 1
        if path.suffix.lower() not in allowed:
            continue
        inventory.candidates.append(
            Candidate(
                source_kind="File",
                source_path=str(path),
                source_name=path.name,
                entry="",
                name=path.name,
                log_type=log_type_from_name(path.name),
                day=date_from_name(path.name),
                size=path.stat().st_size,
            )
        )
    return inventory


def _unique_name(original: str, used: dict[str, int]) -> str:
    safe = Path(original.replace("\\", "/")).name or "logfile.log"
    for character in '<>:"/\\|?*':
        safe = safe.replace(character, "_")
    safe = "".join("_" if ord(char) < 32 else char for char in safe)
    if safe not in used:
        used[safe] = 1
        return safe
    stem = Path(safe).stem
    suffix = Path(safe).suffix
    number = used[safe] + 1
    while True:
        candidate = f"{stem}__{number}{suffix}"
        if candidate not in used:
            break
        number += 1
    used[safe] = number
    used[candidate] = 1
    return candidate


def collect(
    sources: list[str] | tuple[str, ...],
    days: list[str] | tuple[str, ...] | None = None,
    log_types: list[str] | tuple[str, ...] | None = None,
    pairs: list[tuple[str, str]] | None = None,
    collection_directory: str | Path | None = None,
    output_archive: str | Path | None = None,
    extensions=None,
    use_container_date_fallback: bool = False,
    force: bool = False,
    seven_zip_path: str | None = None,
    inventory: Inventory | None = None,
    progress=None,
    cancelled=None,
) -> CollectResult:
    """Copy the selected logs into a folder or an archive, without duplicates.

    A prepared inventory from a previous scan is reused as is; on large or
    network sources reading everything a second time costs minutes.
    """
    if not collection_directory and not output_archive:
        raise ValueError("Either a collection directory or an output archive is required.")
    wanted_days = {str(day) for day in days} if days else set()
    wanted_pairs = {(str(log_type), str(day)) for log_type, day in pairs} if pairs else set()

    if inventory is None:
        # Without a prepared inventory the sources have to be read again, which
        # reports into the first fifth of the progress instead of standing still.
        def scan_progress(value: float) -> None:
            if progress is not None:
                progress(value * 0.2, "Quellen werden gelesen")

        inventory = scan(
            sources,
            extensions=extensions,
            use_container_date_fallback=use_container_date_fallback,
            progress=scan_progress,
            cancelled=cancelled,
        )
    selection = [
        candidate
        for candidate in inventory.candidates
        if candidate.day is not None
        and (
            (candidate.log_type, candidate.day_text) in wanted_pairs
            if wanted_pairs
            else (
                (not wanted_days or candidate.day_text in wanted_days)
                and matches_log_type(candidate.log_type, list(log_types) if log_types else None)
            )
        )
    ]
    if not selection:
        raise ValueError("No matching log file was found. Check the selected days and log types.")

    staging: Path
    temporary_staging = False
    if collection_directory:
        staging = Path(collection_directory)
        if staging.exists() and any(staging.iterdir()) and not force:
            raise FileExistsError(
                "The collection directory is not empty. Choose a new directory or allow adding to it."
            )
        staging.mkdir(parents=True, exist_ok=True)
        manifest_path = Path(str(staging).rstrip("/\\") + ".manifest.csv")
    else:
        archive_path = Path(output_archive)
        # A folder as the target means the archive mode was switched on while the
        # target still pointed at a directory. Overwriting cannot help there, so
        # say what is actually wrong instead of reporting an existing archive.
        if archive_path.is_dir():
            raise FileExistsError(
                "The target is a folder. In archive mode the target has to be a file, for example "
                f"{archive_path.name}.zip."
            )
        if archive_path.exists() and not force:
            raise FileExistsError("The target archive already exists. Allow overwriting it explicitly.")
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        staging = archive_path.parent / f"collect-logs-{uuid.uuid4().hex}"
        staging.mkdir(parents=True, exist_ok=True)
        temporary_staging = True
        manifest_path = archive_path.with_suffix(".manifest.csv")

    known_hashes: dict[str, str] = {}
    used_names: dict[str, int] = {}
    manifest: list[dict] = []
    result = CollectResult(
        archives_scanned=inventory.archives_scanned,
        files_inspected=inventory.files_inspected,
        archive_errors=len(inventory.archive_errors),
        collection_directory=str(staging) if collection_directory else None,
    )
    for source_name, message in inventory.archive_errors:
        manifest.append(
            {
                "Status": "ArchiveError",
                "Date": "",
                "LogType": "",
                "OutputName": "",
                "OriginalName": "",
                "SourceKind": "ZIP",
                "SourceName": source_name,
                "ArchiveEntry": "",
                "Bytes": 0,
                "SHA256": "",
                "Error": message,
            }
        )

    if collection_directory:
        for existing in staging.glob("*"):
            if existing.is_file():
                used_names[existing.name] = 1
                known_hashes[_hash_file(existing)] = existing.name

    try:
        # The scan yields candidates grouped per source, so one open archive at a
        # time is enough; holding dozens open at once is needless on network paths.
        open_path: str | None = None
        open_archive: zipfile.ZipFile | None = None
        try:
            for index, candidate in enumerate(selection):
                if cancelled is not None and cancelled():
                    raise Cancelled("Collection cancelled; the partial output is kept for review.")
                if progress is not None:
                    progress(0.2 + 0.8 * (index + 1) / len(selection), candidate.name)
                if candidate.source_kind == "ZIP":
                    if open_path != candidate.source_path:
                        if open_archive is not None:
                            open_archive.close()
                        open_archive = zipfile.ZipFile(candidate.source_path)
                        open_path = candidate.source_path
                    with open_archive.open(candidate.entry) as stream:
                        entry = _store_stream(stream, candidate, staging, known_hashes, used_names)
                else:
                    with open(candidate.source_path, "rb") as stream:
                        entry = _store_stream(stream, candidate, staging, known_hashes, used_names)
                manifest.append(entry)
                if entry["Status"] == "Selected":
                    result.selected += 1
                    result.bytes_written += int(entry["Bytes"])
                else:
                    result.duplicates += 1
        finally:
            if open_archive is not None:
                open_archive.close()

        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(MANIFEST_COLUMNS))
            writer.writeheader()
            writer.writerows(manifest)
        result.manifest = str(manifest_path)

        if output_archive:
            _build_archive(staging, Path(output_archive), seven_zip_path)
            result.output_archive = str(Path(output_archive))
    finally:
        if temporary_staging and staging.exists() and result.output_archive:
            shutil.rmtree(staging, ignore_errors=True)
    return result


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _store_stream(stream, candidate: Candidate, staging: Path, known_hashes: dict, used_names: dict) -> dict:
    temporary = staging / f"incoming-{uuid.uuid4().hex}.part"
    digest = hashlib.sha256()
    size = 0
    with temporary.open("wb") as handle:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            handle.write(chunk)
    checksum = digest.hexdigest().upper()
    row = {
        "Date": candidate.day_text,
        "LogType": candidate.log_type,
        "OriginalName": candidate.name,
        "SourceKind": candidate.source_kind,
        "SourceName": candidate.source_name,
        "ArchiveEntry": candidate.entry,
        "Bytes": size,
        "SHA256": checksum,
        "Error": "",
    }
    if checksum in known_hashes:
        temporary.unlink(missing_ok=True)
        row.update({"Status": "Duplicate", "OutputName": known_hashes[checksum]})
        return row
    name = _unique_name(candidate.name, used_names)
    os.replace(temporary, staging / name)
    known_hashes[checksum] = name
    row.update({"Status": "Selected", "OutputName": name})
    return row


def find_seven_zip(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if Path(explicit).is_file() else None
    found = shutil.which("7z") or shutil.which("7z.exe")
    if found:
        return found
    for candidate in (
        Path(os.environ.get("ProgramFiles", "")) / "7-Zip" / "7z.exe",
        Path(os.environ.get("ProgramFiles(x86)", "")) / "7-Zip" / "7z.exe",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def _build_archive(staging: Path, target: Path, seven_zip_path: str | None) -> None:
    if target.exists():
        target.unlink()
    if target.suffix.lower() == ".7z":
        seven_zip = find_seven_zip(seven_zip_path)
        if not seven_zip:
            raise FileNotFoundError(
                "7-Zip was not found. Install it, point at 7z.exe explicitly, or use a .zip target "
                "(compressed with LZMA, no external tool needed)."
            )
        completed = subprocess.run(
            [seven_zip, "a", "-t7z", str(target), str(staging / "*"), "-mx=9", "-m0=lzma2", "-ms=on", "-mmt=on", "-bd", "-y"],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0 or not target.exists():
            raise RuntimeError(f"7-Zip could not create the target archive: {completed.stderr.strip()}")
        return

    compression = zipfile.ZIP_LZMA
    try:
        import lzma  # noqa: F401
    except ImportError:
        compression = zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(target, "w", compression=compression) as archive:
        for item in sorted(staging.glob("*")):
            if item.is_file():
                archive.write(item, item.name)
