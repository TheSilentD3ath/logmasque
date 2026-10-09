"""No real person, company or address may appear anywhere in the repository.

Detection works on patterns and context only. A real name in a rule, a test or
a comment would leak it, and would hide that the rule only works for that one
name. The values to look for are real data themselves and therefore never enter
the repository: they come from the local mapping store, which holds every name,
company, street, phone number, register entry and IBAN learned so far, and from
an optional private list with one value per line, named by
LOGMASQUE_PRIVATE_VALUES. LOGMASQUE_GUARD_STORE picks another store file; a store
protected by a password is read with LOGMASQUE_STORE_PASSWORD. With no values
available the test is skipped. A hit names file, line and kind, never the value.
"""

import os
import re
import unittest
from pathlib import Path

from logmasque.store import StoreError, default_store_path, load_mapping

ROOT = Path(__file__).resolve().parents[1]

# Everything that is published: sources, tests, scripts and documentation.
CHECKED = ("logmasque", "tests", "scripts", "docs", "dist")
TOP_LEVEL = ("*.md", "*.toml", "*.txt", "LICENSE", ".gitignore")
SUFFIXES = {".py", ".js", ".html", ".css", ".md", ".json", ".txt", ".toml", ".yml", ".yaml"}
KINDS = ("Person", "Company", "Street", "Phone", "Register", "Account")
WORD = re.compile(r"\w+")


def checked_files() -> list[Path]:
    files = sorted({item for pattern in TOP_LEVEL for item in ROOT.glob(pattern) if item.is_file()})
    for name in CHECKED:
        path = ROOT / name
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(
                item
                for item in sorted(path.rglob("*"))
                if item.is_file() and item.suffix in SUFFIXES and "__pycache__" not in item.parts
            )
    return files


def distinctive(kind: str, value: str) -> bool:
    """Short single words and short numbers would match everywhere by chance."""
    words = WORD.findall(value)
    if not words:
        return False
    if len(words) == 1:
        return len(value) >= (6 if value.isdigit() else 4)
    return True


def private_values() -> list[tuple[str, str]]:
    values = []
    listed = os.environ.get("LOGMASQUE_PRIVATE_VALUES")
    if listed:
        lines = Path(listed).read_text(encoding="utf-8").splitlines()
        values.extend(("List", line.strip()) for line in lines if line.strip() and not line.startswith("#"))
    store = Path(os.environ.get("LOGMASQUE_GUARD_STORE") or default_store_path())
    if store.is_file():
        try:
            mapping = load_mapping(store, os.environ.get("LOGMASQUE_STORE_PASSWORD") or None)
        except StoreError:
            mapping = None
        if mapping is not None:
            values.extend((kind, value) for kind in KINDS for value in mapping.maps[kind])
    return [(kind, value) for kind, value in values if distinctive(kind, value)]


def find_real_values(values: list[tuple[str, str]], files: list[Path]) -> list[str]:
    hits = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        words = set(WORD.findall(text))
        for kind, value in values:
            # Cheap test first: every word of the value has to occur somewhere.
            if not all(word in words for word in WORD.findall(value)):
                continue
            exact = re.compile(rf"(?<!\w){re.escape(value)}(?!\w)")
            for number, line in enumerate(text.splitlines(), 1):
                if exact.search(line):
                    hits.append(f"{path.relative_to(ROOT)}:{number}: {kind}")
    return sorted(set(hits))


class NoRealDataTest(unittest.TestCase):
    def test_code_holds_no_known_real_value(self):
        values = private_values()
        if not values:
            self.skipTest("No local store and no LOGMASQUE_PRIVATE_VALUES list to compare with.")
        hits = find_real_values(values, checked_files())
        self.assertEqual(
            hits, [], "Real data in the code (values are not shown; look at the line):\n" + "\n".join(hits)
        )

    def test_the_guard_finds_what_it_is_given(self):
        sample = ROOT / "tests" / "test_pii.py"
        hits = find_real_values([("Person", "Clara Probe"), ("Person", "Probe")], [sample])
        self.assertTrue(hits)
        self.assertTrue(all(hit.endswith(": Person") for hit in hits))
        self.assertEqual(find_real_values([("Person", "Clara Probex")], [sample]), [])


if __name__ == "__main__":
    unittest.main()
