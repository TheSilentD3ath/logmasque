"""The logmasque command line, run in-process against synthetic files."""

import contextlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from logmasque import __version__, cli

PASSWORD = "Synthetic-Cli-Password-1"
LOG = (
    "Mon 2026-08-26 10:15:01.140: Accepting SMTP connection from 203.0.113.7:52344 to mx1.mail.example.org\n"
    "Mon 2026-08-26 10:15:01.145: RCPT TO:<bob@kunde.example> 250 OK\n"
    "Mon 2026-08-26 10:15:01.150: Session from 2001:db8::5 closed\n"
)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        data = str(self.root / "data")
        for patcher in (
            mock.patch.dict(os.environ, {"XDG_DATA_HOME": data, "LOCALAPPDATA": data}),
            mock.patch.object(cli, "_STORE_PASSWORD", PASSWORD),
            # The log file handler outlives a test; keep it away from the temporary folder.
            mock.patch("logmasque.applog.setup"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, *arguments):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(arguments))
            except SystemExit as stop:
                code = stop.code
        return code, out.getvalue(), err.getvalue()

    def logs(self):
        source = self.root / "source"
        source.mkdir()
        (source / "SMTP-In-2026-08-26.log").write_text(LOG, encoding="utf-8")
        (source / "SMTP-Out-2026-08-26.log").write_text("out\n", encoding="utf-8")
        with zipfile.ZipFile(source / "Logs-2026-08-27.zip", "w") as archive:
            archive.writestr("SMTP-In-2026-08-27.log", "zip entry\n")
            archive.writestr("SMTP-In-2026-08-26.log", LOG)  # duplicate of the loose file
        return source

    # -- general ------------------------------------------------------------

    def test_help_and_version(self):
        code, out, _ = self.run_cli("--help")
        self.assertEqual(code, 0)
        for command in ("ui", "scan", "collect", "anonymize", "mask", "check", "store"):
            self.assertIn(command, out)
        code, out, _ = self.run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn(f"logmasque {__version__}", out)

    def test_no_command_opens_the_interface(self):
        with mock.patch("logmasque.server.serve") as serve:
            code, _, _ = self.run_cli()
        self.assertEqual(code, 0)
        serve.assert_called_once_with(port=0, open_browser=True, debug=False)

    def test_ui_options(self):
        with mock.patch("logmasque.server.serve") as serve:
            code, _, _ = self.run_cli("ui", "--port", "8765", "--no-browser")
        self.assertEqual(code, 0)
        serve.assert_called_once_with(port=8765, open_browser=False, debug=False)

    # -- collecting ---------------------------------------------------------

    def test_scan_lists_types_and_days(self):
        source = self.logs()
        code, out, _ = self.run_cli("scan", str(source), "--json")
        self.assertEqual(code, 0)
        matrix = json.loads(out)
        self.assertEqual(matrix["days"], ["2026-08-26", "2026-08-27"])
        self.assertEqual(sorted(matrix["types"]), ["SMTP-In", "SMTP-Out"])

    def test_collect_into_folder_and_archive(self):
        source = self.logs()
        target = self.root / "selection"
        code, out, _ = self.run_cli("collect", str(source), "--day", "2026-08-26", "--type", "SMTP-In", "--out", str(target))
        self.assertEqual(code, 0, out)
        self.assertIn("1 selected, 1 duplicates", out)
        self.assertEqual([item.name for item in target.iterdir()], ["SMTP-In-2026-08-26.log"])

        archive = self.root / "selection.zip"
        code, _, _ = self.run_cli("collect", str(source), "--day", "2026-08-27", "--archive", str(archive))
        self.assertEqual(code, 0)
        self.assertEqual(zipfile.ZipFile(archive).namelist(), ["SMTP-In-2026-08-27.log"])

    def test_collect_needs_a_target(self):
        code, _, err = self.run_cli("collect", str(self.root), "--day", "2026-08-26")
        self.assertEqual(code, 2)
        self.assertIn("--out or --archive", err)

    # -- masking ------------------------------------------------------------

    def test_anonymize_mask_alias_and_restore(self):
        first = self.root / "first.log"
        second = self.root / "second.log"
        first.write_text(LOG, encoding="utf-8")
        second.write_text("Retry from 203.0.113.7 for bob@kunde.example\n", encoding="utf-8")

        code, out, err = self.run_cli("anonymize", str(first))
        self.assertEqual(code, 0, err)
        masked = (self.root / "first.anonym.log").read_text(encoding="utf-8")
        for original in ("203.0.113.7", "mail.example.org", "bob@", "kunde.example", "2001:db8::5"):
            self.assertNotIn(original, masked)
        self.assertIn("[IPv4-001]", masked)
        self.assertIn("[IPv6-001]", masked)

        # A later run through the alias reuses the placeholders kept in the store.
        code, _, err = self.run_cli("mask", str(second))
        self.assertEqual(code, 0, err)
        self.assertEqual(
            (self.root / "second.anonym.log").read_text(encoding="utf-8"),
            # example.org came first in the earlier file, so kunde.example is the second domain.
            "Retry from [IPv4-001] for user001@kunde002.tld\n",
        )

        code, out, err = self.run_cli("anonymize", str(self.root / "first.anonym.log"), "--restore")
        self.assertEqual(code, 0, err)
        self.assertIn("unknown: 0", out)
        self.assertEqual((self.root / "first.anonym.klartext.log").read_text(encoding="utf-8"), LOG)

    def test_redact_mode_writes_no_store(self):
        source = self.root / "redact.log"
        source.write_text(LOG, encoding="utf-8")
        code, _, err = self.run_cli("anonymize", str(source), "--mode", "redact")
        self.assertEqual(code, 0, err)
        output = (self.root / "redact.anonym.log").read_text(encoding="utf-8")
        self.assertIn("[IP-ENTFERNT]", output)
        self.assertNotIn("203.0.113.7", output)
        self.assertFalse(Path(os.environ["XDG_DATA_HOME"], "Anonymize-Log", "mapping.json").exists())

    def test_existing_output_is_kept_without_force(self):
        source = self.root / "keep.log"
        source.write_text(LOG, encoding="utf-8")
        (self.root / "keep.anonym.log").write_text("earlier result", encoding="utf-8")
        code, _, err = self.run_cli("anonymize", str(source), "--no-store")
        self.assertEqual(code, 0)
        self.assertIn("--force", err)
        self.assertEqual((self.root / "keep.anonym.log").read_text(encoding="utf-8"), "earlier result")

    # -- store --------------------------------------------------------------

    def test_store_info_rows_export_and_import(self):
        source = self.root / "store.log"
        source.write_text(LOG, encoding="utf-8")
        self.assertEqual(self.run_cli("anonymize", str(source))[0], 0)

        code, out, _ = self.run_cli("store", "info")
        self.assertEqual(code, 0)
        info = json.loads(out)
        self.assertTrue(info["readable"])
        self.assertEqual(info["counts"]["IPv4"], 1)

        code, out, _ = self.run_cli("store", "rows")
        self.assertIn("[IPv4-001]", out)

        backup = self.root / "backup.anonstore"
        with mock.patch("getpass.getpass", return_value="Synthetic-Export-Password-1"):
            self.assertEqual(self.run_cli("store", "export", "--file", str(backup))[0], 0)
            code, out, err = self.run_cli("store", "import", "--file", str(backup))
        self.assertEqual(code, 0, err)
        self.assertIn("previous store kept as", out)

    def test_store_needs_file_for_export(self):
        code, _, err = self.run_cli("store", "export")
        self.assertEqual(code, 2)
        self.assertIn("--file", err)


if __name__ == "__main__":
    unittest.main()
