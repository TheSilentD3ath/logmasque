"""The single-file build must be the same program as the package and run on its own."""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_single_file", REPO / "scripts" / "build_single_file.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SingleFileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = _load_builder()
        cls.bundle_text = cls.builder.render()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bundle = self.root / "LogMasque.py"
        with open(self.bundle, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(self.bundle_text)

    def tearDown(self):
        self.temp.cleanup()

    def _run_alone(self, *arguments, env=None):
        # -I keeps PYTHONPATH, the user site and the script folder off sys.path,
        # so only what the bundle carries can be imported.
        return subprocess.run(
            [sys.executable, "-I", str(self.bundle), *arguments],
            cwd=self.root, capture_output=True, text=True, timeout=120, env=env,
        )

    def test_build_script_writes_the_file(self):
        target = self.root / "out" / "LogMasque.py"
        with open(os.devnull, "w") as quiet:
            stdout, sys.stdout = sys.stdout, quiet
            try:
                self.assertEqual(self.builder.main(["--output", str(target)]), 0)
            finally:
                sys.stdout = stdout
        self.assertEqual(target.read_text(encoding="utf-8"), self.bundle_text)

    def test_runs_without_the_package(self):
        from logmasque import __version__

        completed = self._run_alone("--version")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"logmasque {__version__}", completed.stdout + completed.stderr)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["LogMasque.py"])

    def test_help_lists_every_command(self):
        completed = self._run_alone("--help")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for command in ("ui", "scan", "collect", "anonymize", "check", "store"):
            self.assertIn(command, completed.stdout)

    def test_anonymizes_a_file_on_its_own(self):
        source = self.root / "sample.log"
        source.write_text("Connection from 203.0.113.7 for user@mail.example.com\n", encoding="utf-8")
        env = dict(os.environ, LOCALAPPDATA=str(self.root / "data"), XDG_DATA_HOME=str(self.root / "data"))
        completed = self._run_alone("anonymize", "--no-store", str(source), env=env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = (self.root / "sample.anonym.log").read_text(encoding="utf-8")
        self.assertNotIn("203.0.113.7", output)
        self.assertNotIn("mail.example.com", output)
        self.assertIn("[IPv4-001]", output)

    def test_store_self_test(self):
        env = dict(os.environ, LOCALAPPDATA=str(self.root / "data"), XDG_DATA_HOME=str(self.root / "data"))
        completed = self._run_alone("store", "selftest", env=env)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertTrue(completed.stdout.startswith("PASS:"), completed.stdout)

    def test_ignores_a_package_folder_lying_next_to_it(self):
        # Old unpacked ZIPs end up right next to the downloaded file.
        (self.root / "logmasque").mkdir()
        (self.root / "logmasque" / "__init__.py").write_text("raise RuntimeError('stale copy loaded')\n")
        completed = self._run_alone("--version")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("stale copy", completed.stderr)

    def test_tracebacks_show_the_failing_line(self):
        # Errors in the log are only useful with the source line next to them.
        probe = (
            "import runpy, sys, traceback\n"
            "bundle = runpy.run_path(sys.argv[1], run_name='bundle')\n"
            "sys.meta_path.insert(0, bundle['_BundleImporter'](sys.argv[1]))\n"
            "from logmasque.collect import collect\n"
            "try:\n"
            "    collect([], days=['2026-01-01'], collection_directory=sys.argv[2])\n"
            "except Exception as error:\n"
            "    frames = [f for f in traceback.extract_tb(error.__traceback__) if 'LogMasque.py' in f.filename]\n"
            "    print(len(frames), all(f.line for f in frames))\n"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", probe, str(self.bundle), str(self.root / "out")],
            cwd=self.root, capture_output=True, text=True, timeout=120,
        )
        count, has_lines = completed.stdout.split()
        self.assertGreater(int(count), 0, completed.stderr)
        self.assertEqual(has_lines, "True")


if __name__ == "__main__":
    unittest.main()
