"""Collecting logs: filename metadata, selection, deduplication, output."""

import csv
import tempfile
import unittest
import zipfile
from datetime import date
from pathlib import Path

from logmasque.collect import collect, scan
from logmasque.lognames import date_from_name, log_type_from_name, matches_log_type


class Filenames(unittest.TestCase):
    def test_date_formats(self):
        for name in ("Tool-2030-04-06.log", "Tool_2030_04_06.log", "Tool.2030.04.06.log", "Tool-20300406.log"):
            self.assertEqual(date_from_name(name), date(2030, 4, 6), name)

    def test_no_date(self):
        self.assertIsNone(date_from_name("undated.log"))
        self.assertIsNone(date_from_name("Tool-2030-13-45.log"))

    def test_log_types(self):
        cases = {
            "SMTP-In-2026-08-26.log": "SMTP-In",
            "SMTP-Out_2026-08-26.log": "SMTP-Out",
            "MDaemon-2026-08-26-System.log": "MDaemon",
            "AccountPrune_2026-08-27.log": "AccountPrune",
            "AnyPrefix.20260826.txt": "AnyPrefix",
            "undated.log": "undated",
        }
        for name, expected in cases.items():
            self.assertEqual(log_type_from_name(name), expected, name)

    def test_type_patterns(self):
        self.assertTrue(matches_log_type("SMTP-In", ["SMTP-*"]))
        self.assertTrue(matches_log_type("smtp-in", ["SMTP-In"]))
        self.assertFalse(matches_log_type("AntiVirus", ["SMTP-*"]))
        self.assertTrue(matches_log_type("AntiVirus", []))


class Collecting(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.source = self.root / "source"
        self.source.mkdir()
        inner = self.root / "inner"
        inner.mkdir()
        for name, content in (
            ("SMTP-In-2026-08-26.log", "in"),
            ("SMTP-Out-2026-08-26.log", "out"),
            ("MDaemon-2026-08-26-System.log", "sys"),
            ("AccountPrune_2026-08-27.log", "prune"),
            ("HTTP-2026-08-28.log", "http"),
            ("undated.log", "nodate"),
        ):
            (inner / name).write_text(content)
        with zipfile.ZipFile(self.source / "Logs-2026-08-29.zip", "w") as archive:
            for item in inner.iterdir():
                archive.write(item, item.name)
        (self.source / "DynScrn-2026-08-27.log").write_text("dyn")
        (self.source / "SMTP-In-2026-08-26.log").write_text("in")  # identical twin of the zip entry

    def test_scan_matrix(self):
        matrix = scan([str(self.source)]).matrix()
        self.assertEqual(matrix["days"], ["2026-08-26", "2026-08-27", "2026-08-28"])
        self.assertIn("SMTP-In", matrix["types"])
        self.assertEqual(matrix["cells"]["SMTP-In"]["2026-08-26"][0], 2)
        self.assertEqual(matrix["undated"], 1)
        self.assertEqual(matrix["archivesScanned"], 1)

    def test_select_by_day_and_type(self):
        target = self.root / "collected"
        result = collect(
            [str(self.source)],
            days=["2026-08-26", "2026-08-27"],
            log_types=["SMTP-*", "DynScrn"],
            collection_directory=str(target),
        )
        self.assertEqual(result.selected, 3)
        self.assertEqual(result.duplicates, 1)
        self.assertEqual(
            sorted(item.name for item in target.iterdir()),
            ["DynScrn-2026-08-27.log", "SMTP-In-2026-08-26.log", "SMTP-Out-2026-08-26.log"],
        )

    def test_exact_cell_selection(self):
        target = self.root / "pairs"
        result = collect(
            [str(self.source)],
            pairs=[("SMTP-In", "2026-08-26"), ("AccountPrune", "2026-08-27")],
            collection_directory=str(target),
        )
        self.assertEqual(result.selected, 2)
        self.assertEqual(
            sorted(item.name for item in target.iterdir()),
            ["AccountPrune_2026-08-27.log", "SMTP-In-2026-08-26.log"],
        )

    def test_name_collision_keeps_both(self):
        inner = self.root / "other"
        inner.mkdir()
        (inner / "SMTP-In-2026-08-26.log").write_text("different content")
        with zipfile.ZipFile(self.source / "Logs-2026-08-30.zip", "w") as archive:
            archive.write(inner / "SMTP-In-2026-08-26.log", "SMTP-In-2026-08-26.log")
        target = self.root / "collision"
        result = collect([str(self.source)], days=["2026-08-26"], log_types=["SMTP-In"], collection_directory=str(target))
        self.assertEqual(result.selected, 2)
        self.assertTrue((target / "SMTP-In-2026-08-26__2.log").is_file())

    def test_manifest_columns_and_content(self):
        target = self.root / "manifest-run"
        result = collect([str(self.source)], days=["2026-08-26"], collection_directory=str(target))
        with Path(result.manifest).open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(
            list(rows[0]),
            [
                "Status", "Date", "LogType", "OutputName", "OriginalName",
                "SourceKind", "SourceName", "ArchiveEntry", "Bytes", "SHA256", "Error",
            ],
        )
        smtp = [row for row in rows if row["OriginalName"] == "SMTP-Out-2026-08-26.log"][0]
        self.assertEqual(smtp["LogType"], "SMTP-Out")
        self.assertEqual(smtp["Date"], "2026-08-26")
        self.assertEqual(len(smtp["SHA256"]), 64)
        self.assertFalse((target / Path(result.manifest).name).exists())

    def test_zip_archive_output_without_seven_zip(self):
        target = self.root / "export.zip"
        result = collect([str(self.source)], days=["2026-08-26"], output_archive=str(target))
        self.assertTrue(target.is_file())
        self.assertEqual(len(zipfile.ZipFile(target).namelist()), result.selected)
        self.assertFalse(any(item.name.startswith("collect-logs-") for item in self.root.iterdir()))

    def test_non_empty_target_is_refused(self):
        target = self.root / "used"
        target.mkdir()
        (target / "vorhanden.log").write_text("x")
        with self.assertRaises(FileExistsError):
            collect([str(self.source)], days=["2026-08-26"], collection_directory=str(target))

    def test_folder_as_archive_target_names_the_real_problem(self):
        # Switching to archive mode with the target still pointing at a folder
        # used to be reported as "archive already exists", which sends people
        # looking for a file that is not there.
        target = self.root / "Neuer Ordner"
        target.mkdir()
        with self.assertRaises(FileExistsError) as caught:
            collect([str(self.source)], days=["2026-08-26"], output_archive=str(target))
        self.assertIn("folder", str(caught.exception))
        # Overwriting cannot rescue a folder either, so it must refuse there too.
        with self.assertRaises(FileExistsError):
            collect([str(self.source)], days=["2026-08-26"], output_archive=str(target), force=True)

    def test_nothing_matching_is_an_error(self):
        with self.assertRaises(ValueError):
            collect([str(self.source)], days=["2030-01-01"], collection_directory=str(self.root / "empty"))

    def test_container_date_fallback(self):
        matrix = scan([str(self.source)], use_container_date_fallback=True).matrix()
        self.assertEqual(matrix["undated"], 0)
        self.assertEqual(matrix["cells"]["undated"]["2026-08-29"][0], 1)


if __name__ == "__main__":
    unittest.main()
