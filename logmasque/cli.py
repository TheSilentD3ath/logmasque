"""LogMasque command line. Without a command the browser interface starts."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import __version__, applog
from .anonymize import Anonymizer, Options, default_output_path, find_leaks, read_text
from .collect import collect, scan
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
    self_test,
    store_needs_password,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logmasque", description=__doc__)
    parser.add_argument("--version", action="version", version=f"logmasque {__version__}")
    commands = parser.add_subparsers(dest="command")

    parser.add_argument("--debug", action="store_true", help="write verbose entries to the log file")

    ui = commands.add_parser("ui", help="start the local interface (default)")
    ui.add_argument("--port", type=int, default=0)
    ui.add_argument("--no-browser", action="store_true")

    scan_command = commands.add_parser("scan", help="list log types and days found in sources")
    scan_command.add_argument("sources", nargs="+")
    scan_command.add_argument("--json", action="store_true")
    scan_command.add_argument("--extension", action="append", dest="extensions")

    collect_command = commands.add_parser("collect", help="copy selected logs into a folder or archive")
    collect_command.add_argument("sources", nargs="+")
    collect_command.add_argument("--day", action="append", dest="days", help="repeatable, format yyyy-MM-dd")
    collect_command.add_argument("--type", action="append", dest="log_types", help="repeatable, wildcards allowed")
    collect_command.add_argument("--out", help="collection directory")
    collect_command.add_argument("--archive", help="target .zip (LZMA) or .7z")
    collect_command.add_argument("--extension", action="append", dest="extensions")
    collect_command.add_argument("--container-date-fallback", action="store_true")
    collect_command.add_argument("--force", action="store_true")

    anonymize = commands.add_parser(
        "anonymize", aliases=["mask"], help="write anonymized copies of log files"
    )
    anonymize.add_argument("files", nargs="+")
    anonymize.add_argument("--out", help="output directory, default: next to the source")
    anonymize.add_argument("--mode", choices=("pseudonym", "redact"), default="pseudonym")
    anonymize.add_argument("--keep-private-ip", action="store_true")
    anonymize.add_argument("--keep-hostnames", action="store_true", help="do not replace host labels")
    anonymize.add_argument("--keep-domain", action="append", dest="keep_domains")
    anonymize.add_argument("--extra-pattern", action="append", dest="extra_patterns")
    anonymize.add_argument(
        "--no-personal", action="store_true", help="do not look for names, phone numbers and addresses in text"
    )
    anonymize.add_argument("--encoding", default="auto")
    anonymize.add_argument("--no-store", action="store_true", help="do not read or write the mapping store")
    anonymize.add_argument("--store", dest="store_path", help="alternative store file")
    anonymize.add_argument("--restore", action="store_true", help="turn placeholders back into originals")
    anonymize.add_argument("--mapping-csv", help="also write a plain mapping CSV (sensitive)")
    anonymize.add_argument("--force", action="store_true")

    check = commands.add_parser(
        "check", help="count what still looks personal in anonymized files, without printing it"
    )
    check.add_argument("files", nargs="+")
    check.add_argument("--encoding", default="auto")
    check.add_argument("--no-store", action="store_true", help="do not use the names the store knows")
    check.add_argument("--store", dest="store_path", help="alternative store file")

    store = commands.add_parser("store", help="inspect, export, import or reset the mapping store")
    store.add_argument("action", choices=("info", "check", "selftest", "export", "import", "reset", "rows"))
    store.add_argument("--file", help=".anonstore file for export or import")
    store.add_argument("--store", dest="store_path")
    store.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(argv)
    except KeyboardInterrupt:
        return 130
    except (FileNotFoundError, FileExistsError, ValueError, OSError, StoreError) as error:
        print(f"{error}", file=sys.stderr)
        return 2


def _run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    command = arguments.command or "ui"
    if command == "mask":
        command = "anonymize"

    if command == "ui":
        from .server import serve

        serve(
            port=getattr(arguments, "port", 0),
            open_browser=not getattr(arguments, "no_browser", False),
            debug=arguments.debug,
        )
        return 0

    applog.setup(debug=arguments.debug)
    applog.get().info("command %s", command)

    if command == "scan":
        inventory = scan(arguments.sources, extensions=arguments.extensions)
        matrix = inventory.matrix()
        if arguments.json:
            print(json.dumps(matrix, indent=2))
            return 0
        print(f"{matrix['total']} dated files, {matrix['undated']} without a date")
        width = max((len(name) for name in matrix["types"]), default=8)
        header = " " * (width + 2) + "  ".join(day[5:] for day in matrix["days"])
        print(header)
        for log_type in matrix["types"]:
            row = [f"{log_type:<{width}}"]
            for day in matrix["days"]:
                cell = matrix["cells"].get(log_type, {}).get(day)
                row.append(f"{cell[0]:>5}" if cell else "    ·")
            print("  ".join(row))
        for error in matrix["archiveErrors"]:
            print(f"ZIP error in {error['source']}: {error['error']}", file=sys.stderr)
        return 0

    if command == "collect":
        if not arguments.out and not arguments.archive:
            parser.error("either --out or --archive is required")
        result = collect(
            arguments.sources,
            days=arguments.days,
            log_types=arguments.log_types,
            collection_directory=arguments.out,
            output_archive=arguments.archive,
            extensions=arguments.extensions,
            use_container_date_fallback=arguments.container_date_fallback,
            force=arguments.force,
        )
        target = result.output_archive or result.collection_directory
        print(f"{result.selected} selected, {result.duplicates} duplicates -> {target}")
        print(f"Manifest (local only): {result.manifest}")
        return 0

    if command == "anonymize":
        store_path = arguments.store_path or str(default_store_path())
        mapping = Mapping() if arguments.no_store else _open_store(store_path)
        options = Options(
            mode=arguments.mode,
            keep_private_ip=arguments.keep_private_ip,
            anonymize_hostname=not arguments.keep_hostnames,
            keep_domains=tuple(arguments.keep_domains or ()),
            extra_patterns=tuple(arguments.extra_patterns or ()),
            detect_personal=not arguments.no_personal,
        )
        engine = Anonymizer(mapping, options)
        writes_store = not arguments.no_store and not arguments.restore and arguments.mode != "redact"
        if writes_store and store_needs_password(_STORE_PASSWORD):
            _set_store_password(
                getpass.getpass("Password to protect the local mapping store (at least 12 characters): ")
            )
        if arguments.out:
            Path(arguments.out).mkdir(parents=True, exist_ok=True)
        for name in arguments.files:
            source = Path(name)
            target = default_output_path(source, arguments.out, arguments.restore)
            if target.exists() and not arguments.force:
                print(f"Output file already exists (use --force): {target}", file=sys.stderr)
                continue
            lines = engine.process_file(source, target, encoding=arguments.encoding, restore=arguments.restore)
            print(f"{source}  ->  {target}  ({lines} lines)")
        if not arguments.no_store and not arguments.restore and arguments.mode != "redact":
            backup = save_mapping(store_path, mapping, password=_STORE_PASSWORD)
            if backup:
                print(f"Previous store kept as {backup}")
        if arguments.mapping_csv:
            _write_csv(mapping, arguments.mapping_csv)
            print(f"Mapping file written: {arguments.mapping_csv} - never share it.")
        if arguments.restore:
            print(f"Restored: {engine.restored}, unknown: {engine.unresolved}")
        else:
            print(
                "Replaced: "
                + ", ".join(f"{count} {name}" for name, count in engine.stats.items() if count)
                or "Nothing replaced."
            )
        return 0

    if command == "check":
        mapping = None
        if not arguments.no_store:
            store_path = arguments.store_path or str(default_store_path())
            try:
                mapping = load_mapping(store_path, _STORE_PASSWORD)
            except PasswordRequired:
                # Asked only at a terminal; a scripted run checks without the known names.
                if sys.stdin.isatty():
                    mapping = _open_store(store_path)
                else:
                    print("Store not used: it needs a password. Names it knows are not checked.", file=sys.stderr)
            except StoreError as error:
                print(f"Store not used: {error}", file=sys.stderr)
        found_any = False
        for name in arguments.files:
            # A copy per file: the check must neither change the store nor carry names between files.
            copy = Mapping.from_store_dict(mapping.to_store_dict()) if mapping is not None else None
            counts = find_leaks(read_text(name, arguments.encoding), copy)
            found_any = found_any or bool(counts)
            summary = ", ".join(f"{count} {label}" for label, count in sorted(counts.items()))
            print(f"{name}: {summary or 'nothing found'}")
        print(
            "Only counts are shown, never the values. A person still has to read the text before it is shared."
        )
        return 2 if found_any else 0

    if command == "store":
        store_path = arguments.store_path or str(default_store_path())
        if arguments.action == "selftest":
            try:
                protection = self_test()
            except StoreError as error:
                print(f"FAIL: {error}")
                return 2
            print(f"PASS: a store protected with {protection} can be written and read back on this system.")
            return 0
        if arguments.action == "check":
            report = check_store(store_path, _STORE_PASSWORD)
            width = max(len(label) for label, _ in report)
            for label, value in report:
                print(f"{label:<{width}}  {value}")
            return 0
        if arguments.action == "info":
            info = describe_store(store_path, _STORE_PASSWORD)
            print(json.dumps({key: value for key, value in vars(info).items()}, indent=2, default=str))
            return 0
        if arguments.action == "rows":
            for category, original, token in _open_store(store_path).rows():
                print(f"{category:<8} {token:<18} {original}")
            return 0
        if arguments.action == "reset":
            backup = backup_store(store_path)
            Path(store_path).unlink(missing_ok=True)
            print(f"Store reset. Backup: {backup}" if backup else "No store to reset.")
            return 0
        if not arguments.file:
            parser.error("--file is required for export and import")
        password = getpass.getpass("Password for the portable file (at least 12 characters): ")
        if arguments.action == "export":
            _open_store(store_path)  # prompts for the store password when one is needed
            export_portable(store_path, arguments.file, password, force=arguments.force, store_password=_STORE_PASSWORD)
            print(f"Exported: {arguments.file}")
        else:
            backup = import_portable(arguments.file, store_path, password, force=True, store_password=_STORE_PASSWORD)
            print(f"Imported into {store_path}" + (f", previous store kept as {backup}" if backup else ""))
        return 0

    parser.print_help()
    return 1


# Set for scripted runs on systems without DPAPI; otherwise the password is asked for.
_STORE_PASSWORD: str | None = os.environ.get("LOGMASQUE_STORE_PASSWORD") or None


def _set_store_password(value: str) -> None:
    global _STORE_PASSWORD
    _STORE_PASSWORD = value


def _open_store(store_path: str) -> Mapping:
    """Load the store, asking for its password only when it is protected by one."""
    try:
        return load_mapping(store_path, _STORE_PASSWORD)
    except PasswordRequired:
        _set_store_password(getpass.getpass("Password of the local mapping store: "))
        return load_mapping(store_path, _STORE_PASSWORD)


def _write_csv(mapping: Mapping, target: str) -> None:
    import csv

    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Typ", "Original", "Token"])
        writer.writerows(mapping.rows())
