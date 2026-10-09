"""The token mapping that makes pseudonyms stable and reversible.

Each category is a dictionary from the original value to its token. The first
six categories are the ones every store has had from the start; the text
categories hold personal data found in free text such as mails. Besides the
replacements the store keeps three user lists: own terms and own patterns that
are always replaced, and values that are never replaced. Taking a term off its
list keeps its token, so text anonymized earlier can still be restored.
"""

from __future__ import annotations

import re
from datetime import datetime

# Every store written so far has exactly these; older backups carry nothing else.
BASE_CATEGORIES = ("IPv4", "IPv6", "Domain", "Local", "Host", "Extra")
TEXT_CATEGORIES = ("Person", "Company", "Phone", "Street", "City", "Register", "Account")
CATEGORIES = BASE_CATEGORIES + TEXT_CATEGORIES

TOKEN_TEMPLATES = {
    "IPv4": "[IPv4-{:03d}]",
    "IPv6": "[IPv6-{:03d}]",
    "Domain": "kunde{:03d}.tld",
    "Local": "user{:03d}",
    "Host": "host{:03d}",
    "Extra": "[WERT-{:03d}]",
    "Person": "[PERSON-{:03d}]",
    "Company": "[FIRMA-{:03d}]",
    "Phone": "[TEL-{:03d}]",
    "Street": "[STRASSE-{:03d}]",
    "City": "[ORT-{:03d}]",
    "Register": "[REGISTER-{:03d}]",
    "Account": "[KONTO-{:03d}]",
}

# A person shares one number across the full name and its parts, so
# "[PERSON-004]" and "Herr [NAME-004]" read as the same person.
PERSON_PARTS = {"full": "[PERSON-{:03d}]", "surname": "[NAME-{:03d}]", "first": "[VORNAME-{:03d}]"}

# Words and names are matched regardless of case: "Muster" and "MUSTER" are one person.
CASELESS = frozenset(TEXT_CATEGORIES) | {"Extra"}

_TRAILING_NUMBER = re.compile(r"(\d+)(?!.*\d)")
_PERSON_TOKEN = re.compile(r"\[(PERSON|NAME|VORNAME)-(\d+)\]", re.IGNORECASE)


class Mapping:
    """Original value -> token, per category, with continuing numbering."""

    def __init__(self) -> None:
        self.maps: dict[str, dict[str, str]] = {name: {} for name in CATEGORIES}
        self.counters: dict[str, int] = {name: 0 for name in CATEGORIES}
        self._folded: dict[str, dict[str, str]] = {name: {} for name in CASELESS}
        self.ignored: dict[str, str] = {}
        self.terms: list[str] = []
        self.patterns: list[str] = []
        self.revision = 0

    # -- lookup and allocation ---------------------------------------------

    def find(self, category: str, key: str) -> str | None:
        """The stored original for key in this category, if any."""
        if category in CASELESS:
            return self._folded[category].get(key.casefold())
        return key if key in self.maps[category] else None

    def token(self, category: str, key: str) -> str:
        existing = self.find(category, key)
        if existing is not None:
            return self.maps[category][existing]
        self.counters[category] += 1
        return self._store(category, key, TOKEN_TEMPLATES[category].format(self.counters[category]))

    def person_token(self, name: str, part: str = "full", number: int | None = None) -> str:
        """Token for a person's full name, surname or first name.

        A part reuses the number of the person it belongs to when that token is
        still free, so the reader can link "[NAME-004]" to "[PERSON-004]".
        """
        existing = self.find("Person", name)
        if existing is not None:
            return self.maps["Person"][existing]
        template = PERSON_PARTS[part]
        used = set(self.maps["Person"].values())
        if number is None or template.format(number) in used:
            self.counters["Person"] += 1
            number = self.counters["Person"]
        return self._store("Person", name, template.format(number))

    @staticmethod
    def person_number(token: str) -> int | None:
        match = _PERSON_TOKEN.fullmatch(token)
        return int(match.group(2)) if match else None

    def _store(self, category: str, key: str, token: str) -> str:
        self.maps[category][key] = token
        if category in CASELESS:
            self._folded[category][key.casefold()] = key
        match = _TRAILING_NUMBER.search(token)
        if match and int(match.group(1)) > self.counters[category]:
            self.counters[category] = int(match.group(1))
        self.revision += 1
        return token

    def remove(self, category: str, key: str) -> bool:
        existing = self.find(category, key)
        if existing is None:
            return False
        del self.maps[category][existing]
        if category in CASELESS:
            self._folded[category].pop(existing.casefold(), None)
        self.revision += 1
        return True

    # -- user lists ----------------------------------------------------------

    def is_ignored(self, value: str) -> bool:
        return bool(self.ignored) and value.strip().casefold() in self.ignored

    def ignore(self, value: str) -> None:
        value = value.strip()
        if value:
            self.ignored[value.casefold()] = value
            self.revision += 1

    def unignore(self, value: str) -> bool:
        removed = self.ignored.pop(value.strip().casefold(), None) is not None
        self.revision += removed
        return removed

    def add_term(self, term: str) -> str:
        """Put a plain term on the list and return the token it is replaced by."""
        term = term.strip()
        if not term:
            raise ValueError("A term must not be empty.")
        if term.casefold() not in {item.casefold() for item in self.terms}:
            self.terms.append(term)
            self.revision += 1
        return self.token("Extra", term)

    def remove_term(self, term: str) -> bool:
        folded = term.strip().casefold()
        kept = [item for item in self.terms if item.casefold() != folded]
        removed = len(kept) != len(self.terms)
        self.terms = kept
        self.revision += removed
        return removed

    def add_pattern(self, pattern: str) -> None:
        re.compile(pattern)  # refuse broken patterns before they are stored
        if pattern not in self.patterns:
            self.patterns.append(pattern)
            self.revision += 1

    def remove_pattern(self, pattern: str) -> bool:
        if pattern in self.patterns:
            self.patterns.remove(pattern)
            self.revision += 1
            return True
        return False

    # -- reporting -------------------------------------------------------------

    @property
    def entry_count(self) -> int:
        return sum(len(values) for values in self.maps.values())

    def counts(self) -> dict[str, int]:
        return {name: len(self.maps[name]) for name in CATEGORIES}

    def rows(self) -> list[tuple[str, str, str]]:
        result = [
            (name, original, token)
            for name in CATEGORIES
            for original, token in self.maps[name].items()
        ]
        result.sort(key=lambda row: (row[0], row[2]))
        return result

    def reverse(self) -> dict[str, dict[str, str]]:
        """Token (lowercased) -> original value, per category."""
        return {
            name: {token.lower(): original for original, token in values.items()}
            for name, values in self.maps.items()
        }

    # -- persistence -------------------------------------------------------------

    def to_store_dict(self) -> dict:
        data: dict[str, object] = {
            "Version": 2,
            "Updated": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        }
        for name in CATEGORIES:
            data[name] = dict(self.maps[name])
        data["Terms"] = list(self.terms)
        data["Patterns"] = list(self.patterns)
        data["Ignore"] = sorted(self.ignored.values(), key=str.casefold)
        return data

    @classmethod
    def from_store_dict(cls, data: dict) -> "Mapping":
        mapping = cls()
        for name in CATEGORIES:
            node = data.get(name) or {}
            if not isinstance(node, dict):
                continue
            for key, token in node.items():
                mapping._store(name, key, str(token))
        for value in data.get("Ignore") or []:
            mapping.ignore(str(value))
        for term in data.get("Terms") or []:
            if str(term).strip() and str(term).casefold() not in {t.casefold() for t in mapping.terms}:
                mapping.terms.append(str(term).strip())
        for pattern in data.get("Patterns") or []:
            try:
                mapping.add_pattern(str(pattern))
            except re.error:
                continue
        mapping.revision = 0
        return mapping

    def same_content(self, other: "Mapping") -> bool:
        return (
            self.maps == other.maps
            and self.ignored == other.ignored
            and self.terms == other.terms
            and self.patterns == other.patterns
        )

    def user_lists_from(self, other: "Mapping") -> None:
        """Take over terms, patterns and the never-replace list, not the tokens."""
        self.terms = list(other.terms)
        self.patterns = list(other.patterns)
        self.ignored = dict(other.ignored)
        self.revision += 1
