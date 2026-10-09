"""Anonymization engine: detect, replace and restore sensitive log values.

The detection rules, token shapes and placeholder texts are the ones the
existing mapping store was built with, so its tokens stay valid. Every line is
walked once with a single combined pattern, which is fast and gives exact match
positions for the highlighted preview.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import pii
from .mapping import Mapping

MULTI_LABEL_SUFFIXES = frozenset(
    """
    co.uk org.uk me.uk ltd.uk plc.uk net.uk sch.uk ac.uk gov.uk
    com.au net.au org.au edu.au gov.au id.au
    co.nz net.nz org.nz govt.nz
    co.za org.za net.za
    co.jp or.jp ne.jp ac.jp go.jp
    com.br net.br org.br gov.br
    com.cn net.cn org.cn gov.cn
    co.in net.in org.in gov.in
    com.tr com.mx com.ar com.pl com.sg com.hk com.tw
    gv.at ac.at co.at priv.at or.at
    """.split()
)

NON_TLD_SUFFIXES = frozenset(
    """
    dll exe log txt dat ini xml msg eml tmp bak cfg mrk sem csv json ps1 bat
    cmd zip gz html htm js css pdf png jpg gif db fdb mdb sys lst idx tld
    """.split()
)

# Abbreviations with a dot inside that look like a domain to the pattern;
# Italian mail is full of them ("Gentile Sig.ra", "Spett.le").
NOT_A_DOMAIN = frozenset("sig.ra sig.na spett.le gent.mo gent.ma gent.mi egr.io dott.ssa ing.re".split())

REDACTION_PLACEHOLDERS = {
    "IPv4": "[IP-ENTFERNT]",
    "IPv6": "[IPV6-ENTFERNT]",
    "Mail": "[MAIL-ENTFERNT]",
    "Domain": "[DOMAIN-ENTFERNT]",
    "Ptr": "[PTR-ENTFERNT]",
    "Extra": "[ENTFERNT]",
    "Person": "[NAME-ENTFERNT]",
    "Company": "[FIRMA-ENTFERNT]",
    "Phone": "[TEL-ENTFERNT]",
    "Street": "[ANSCHRIFT-ENTFERNT]",
    "City": "[ORT-ENTFERNT]",
    "Register": "[REGISTER-ENTFERNT]",
    "Account": "[KONTO-ENTFERNT]",
}

CATEGORY_LABELS = {
    "IPv4": "IPv4 address",
    "IPv6": "IPv6 address",
    "Mail": "Email address",
    "Domain": "Domain",
    "Ptr": "PTR record",
    "Extra": "Own term",
    "Person": "Name",
    "Company": "Company",
    "Phone": "Phone number",
    "Street": "Street",
    "City": "Postcode and city",
    "Register": "Register number",
    "Account": "IBAN",
}

_IPV4 = r"(?<![\w.-])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.-])"
_IPV6 = (
    r"(?<![0-9A-Fa-f:.])(?:"
    r"::[fF]{4}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
    r"|::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,7})"
    r")(?![0-9A-Fa-f:.])"
)
_MAIL = (
    r"(?<![\w.+-])[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)
_FQDN = (
    r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})(?![\w@-])"
)
_ARPA = r"(?<![\w.-])(?:(?:\d{1,3}\.){1,4}in-addr\.arpa|(?:[0-9A-Fa-f]\.){1,32}ip6\.arpa)\.?(?![\w-])"

# One pass; the order of the alternatives decides which kind wins an overlap.
BUILTIN_PATTERN = re.compile(
    f"(?P<arpa>{_ARPA})|(?P<ipv6>{_IPV6})|(?P<ipv4>{_IPV4})|(?P<mail>{_MAIL})|(?P<fqdn>{_FQDN})",
    re.IGNORECASE,
)

_RESTORE_PATTERNS = (
    ("ptr4", re.compile(r"\[IPv4-\d+\]\.in-addr\.arpa", re.IGNORECASE)),
    ("ipv4", re.compile(r"\[IPv4-\d+\]", re.IGNORECASE)),
    ("ipv6", re.compile(r"\[IPv6-\d+\]", re.IGNORECASE)),
    ("extra", re.compile(r"\[WERT-\d+\]", re.IGNORECASE)),
    ("person", re.compile(r"\[(?:PERSON|NAME|VORNAME)-\d+\]", re.IGNORECASE)),
    ("company", re.compile(r"\[FIRMA-\d+\]", re.IGNORECASE)),
    ("phone", re.compile(r"\[TEL-\d+\]", re.IGNORECASE)),
    ("street", re.compile(r"\[STRASSE-\d+\]", re.IGNORECASE)),
    ("city", re.compile(r"\[ORT-\d+\]", re.IGNORECASE)),
    ("register", re.compile(r"\[REGISTER-\d+\]", re.IGNORECASE)),
    ("account", re.compile(r"\[KONTO-\d+\]", re.IGNORECASE)),
    ("domain", re.compile(r"(?<![\w-])kunde\d+\.tld(?![\w-])", re.IGNORECASE)),
    ("host", re.compile(r"(?<![\w-])host\d+(?![\w-])", re.IGNORECASE)),
    ("local", re.compile(r"(?<![\w.-])user\d+(?![\w-])", re.IGNORECASE)),
)


@dataclass
class Options:
    mode: str = "pseudonym"
    keep_private_ip: bool = False
    anonymize_hostname: bool = True
    keep_domains: tuple[str, ...] = ()
    extra_patterns: tuple[str, ...] = ()
    # Names, phone numbers, addresses and companies in free text such as mails.
    detect_personal: bool = True

    @property
    def redact(self) -> bool:
        return self.mode.lower() == "redact"

    def normalized_keep_domains(self) -> set[str]:
        return {item.strip().rstrip(".").lower() for item in self.keep_domains if item and item.strip()}


@dataclass
class Segment:
    """A piece of an output line: either untouched text or one replacement."""

    text: str
    category: str | None = None
    original: str = ""


@dataclass
class Result:
    lines: int = 0
    stats: dict[str, int] = field(default_factory=dict)
    unknown_tokens: list[str] = field(default_factory=list)
    restored: int = 0
    unresolved: int = 0


def is_private_ipv4(value: str) -> bool:
    try:
        parts = [int(part) for part in value.split(".")]
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    a, b, c, d = parts
    return (
        a in (0, 10, 127)
        or (a == 192 and b == 168)
        or (a == 172 and 16 <= b <= 31)
        or (a == 169 and b == 254)
        or (a, b, c, d) == (255, 255, 255, 255)
    )


def normalize_ipv6(value: str) -> str:
    """Match .NET's IPAddress.ToString(), which keeps IPv4-mapped notation."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value.lower()
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return f"::ffff:{address.ipv4_mapped}"
    return str(address).lower()


class Anonymizer:
    def __init__(self, mapping: Mapping, options: Options | None = None) -> None:
        self.mapping = mapping
        self.options = options or Options()
        self.stats: dict[str, int] = {name: 0 for name in CATEGORY_LABELS}
        self._keep_domains = self.options.normalized_keep_domains()
        patterns = list(self.options.extra_patterns) + list(mapping.patterns)
        self._extra_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in dict.fromkeys(patterns) if pattern]
        self._literal_cache: tuple[int, re.Pattern | None, pii.NameIndex] | None = None
        self._cache: dict[str, str] = {}
        self._reverse: dict[str, dict[str, str]] | None = None
        self.restored = 0
        self.unresolved = 0
        self.unknown_tokens: dict[str, bool] = {}

    # -- anonymize ---------------------------------------------------------

    @property
    def _personal_passes(self):
        passes = self.__dict__.get("_passes")
        if passes is None:
            passes = self.__dict__["_passes"] = (
                ("register", pii.REGISTER, self._replace_register),
                ("iban", pii.IBAN, self._replace_iban),
                ("phone_labelled", pii.PHONE_LABELLED, self._replace_labelled_phone),
                ("phone", pii.PHONE_INTERNATIONAL, self._replace_phone),
                ("street", pii.STREET, self._replace_street),
                ("city", pii.CITY, self._replace_city),
                ("company", pii.COMPANY, self._replace_company),
            )
        return passes

    def segments(self, line: str) -> list[Segment]:
        terms, names = self._literals()
        parts: list[Segment] = [Segment(line)]
        for regex in self._extra_regexes:
            parts = self._apply(parts, regex, self._replace_extra)
        if terms is not None:
            parts = self._apply(parts, terms, self._replace_extra)
        parts = self._apply(parts, BUILTIN_PATTERN, self._replace_builtin)
        if not self.options.detect_personal:
            return parts
        if names:
            parts = self._apply(parts, names, self._replace_known)
        wanted = pii.wanted_passes(line)
        if wanted:
            for name, regex, handler in self._personal_passes:
                if name in wanted:
                    parts = self._apply(parts, regex, handler)
        return parts

    # -- personal data in free text -------------------------------------------

    def learn_text(self, text: str) -> None:
        """Learn the names a text reveals before any line of it is replaced."""
        if self.options.detect_personal:
            self._register(pii.learn(text))

    def learn_lines(self, lines, cancelled=None) -> None:
        """Learn from a long input in blocks; a short overlap keeps a closing and
        the name on the following line together."""
        if not self.options.detect_personal:
            return
        findings = pii.Findings()
        block: list[str] = []
        for line in lines:
            block.append(line)
            if len(block) >= 400:
                if cancelled is not None and cancelled():
                    raise Cancelled("Cancelled while reading.")
                findings.merge(pii.learn("\n".join(block)))
                block = block[-3:]
        if block:
            findings.merge(pii.learn("\n".join(block)))
        self._register(findings)

    def _register(self, findings: "pii.Findings") -> None:
        mapping = self.mapping
        numbers: dict[str, int] = {}
        for full in findings.full:
            if mapping.is_ignored(full):
                continue
            number = mapping.person_number(mapping.person_token(full, "full"))
            words = full.split()
            numbers.setdefault("first:" + words[0].casefold(), number)
            numbers.setdefault("last:" + words[-1].casefold(), number)
            surname = words[-1]
            # A full name also gives its surname, so "Muster" alone is caught too.
            if len(surname) >= 3 and not mapping.is_ignored(surname) and mapping.find("Person", surname) is None:
                mapping.person_token(surname, "surname", number)
        for part, values in (("surname", findings.surname), ("first", findings.first)):
            for value in values:
                if mapping.is_ignored(value):
                    continue
                key = ("last:" if part == "surname" else "first:") + value.casefold()
                mapping.person_token(value, part, numbers.get(key))
        for company in findings.company:
            if company and not mapping.is_ignored(company):
                mapping.token("Company", company)
        for city in findings.city:
            if not mapping.is_ignored(city):
                mapping.token("City", city)

    def _literals(self) -> tuple[re.Pattern | None, "pii.NameIndex"]:
        """Own terms, and every known name, company and address, as two patterns."""
        revision = self.mapping.revision
        if self._literal_cache is None or self._literal_cache[0] != revision:
            maps = self.mapping.maps
            terms = [term for term in self.mapping.terms if not self.mapping.is_ignored(term)]
            names = [
                key
                for category in ("Person", "Company", "Street", "City")
                for key in maps[category]
                if not self.mapping.is_ignored(key)
            ]
            self._literal_cache = (revision, _term_pattern(terms), pii.NameIndex(names))
        return self._literal_cache[1], self._literal_cache[2]

    def _known_category(self, value: str) -> str | None:
        for category in ("Person", "Company", "Street", "City"):
            if self.mapping.find(category, value) is not None:
                return category
        return None

    def _personal(self, category: str, value: str) -> str:
        self.stats[category] += 1
        if self.options.redact:
            return REDACTION_PLACEHOLDERS[category]
        if category == "Person":
            existing = self.mapping.find("Person", value)
            if existing is not None:
                return self.mapping.maps["Person"][existing]
            return self.mapping.person_token(value, "surname")
        return self.mapping.token(category, value)

    def _replace_known(self, match: re.Match):
        category = self._known_category(match.group(0))
        if category is None:
            return None
        return self._personal(category, match.group(0)), category

    def _replace_register(self, match: re.Match):
        return self._personal("Register", match.group(0)), "Register"

    def _replace_iban(self, match: re.Match):
        if not pii.valid_iban(match.group(0)):
            return None
        return self._personal("Account", match.group(0)), "Account"

    def _replace_labelled_phone(self, match: re.Match):
        number = match.group("number")
        if not pii.phone_digits_ok(number) or self.mapping.is_ignored(number):
            return None
        return self._personal("Phone", number), "Phone", match.start("number"), match.end("number")

    def _replace_phone(self, match: re.Match):
        if not pii.phone_digits_ok(match.group(0)):
            return None
        return self._personal("Phone", match.group(0)), "Phone"

    def _replace_street(self, match: re.Match):
        return self._personal("Street", match.group(0)), "Street"

    def _replace_city(self, match: re.Match):
        raw = match.group(0)
        start = match.start() + len(raw) - len(raw.lstrip())
        value = pii.trim_city(raw)
        if not pii.city_ok(value) or self.mapping.is_ignored(value):
            return None
        end = start + len(value) if raw.strip().startswith(value) else match.end()
        return self._personal("City", value), "City", start, end

    def _replace_company(self, match: re.Match):
        raw = match.group(0)
        value = pii.clean_company(raw)
        if not value or self.mapping.is_ignored(value):
            return None
        start = match.start() + raw.rfind(value) if value in raw else match.start()
        return self._personal("Company", value), "Company", start, start + len(value)

    def process_line(self, line: str) -> str:
        return "".join(segment.text for segment in self.segments(line))

    def _apply(self, parts: list[Segment], regex: re.Pattern, handler) -> list[Segment]:
        result: list[Segment] = []
        for segment in parts:
            if segment.category is not None:
                result.append(segment)
                continue
            position = 0
            text = segment.text
            for match in regex.finditer(text):
                if self.mapping.is_ignored(match.group(0)):
                    continue
                replacement = handler(match)
                if replacement is None:
                    continue
                # A handler may replace only part of the match, such as the
                # number after "Tel.", and leave the label as it is.
                token, category = replacement[0], replacement[1]
                start, end = (replacement[2], replacement[3]) if len(replacement) == 4 else match.span()
                if start > position:
                    result.append(Segment(text[position:start]))
                result.append(Segment(token, category, text[start:end]))
                position = end
            if position < len(text):
                result.append(Segment(text[position:]))
        return [segment for segment in result if segment.text or segment.category]

    def _replace_extra(self, match: re.Match) -> tuple[str, str] | None:
        self.stats["Extra"] += 1
        if self.options.redact:
            return REDACTION_PLACEHOLDERS["Extra"], "Extra"
        return self.mapping.token("Extra", match.group(0)), "Extra"

    def _replace_builtin(self, match: re.Match) -> tuple[str, str] | None:
        kind = match.lastgroup
        value = match.group(0)
        if kind == "arpa":
            return self._replace_arpa(value)
        if kind == "ipv6":
            return self._replace_ipv6(value)
        if kind == "ipv4":
            return self._replace_ipv4(value)
        if kind == "mail":
            return self._replace_mail(value)
        return self._replace_fqdn(value)

    def _replace_arpa(self, value: str) -> tuple[str, str] | None:
        lowered = value.rstrip(".").lower()
        if lowered.endswith(".in-addr.arpa"):
            octets = lowered[: -len(".in-addr.arpa")].split(".")
            if len(octets) != 4:
                return None
            address = ".".join(reversed(octets))
            if self.options.keep_private_ip and is_private_ipv4(address):
                return None
            self.stats["IPv4"] += 1
            if self.options.redact:
                return REDACTION_PLACEHOLDERS["Ptr"], "Ptr"
            key = ".".join(str(int(part)) for part in address.split("."))
            return self.mapping.token("IPv4", key) + ".in-addr.arpa", "Ptr"
        if lowered.endswith(".ip6.arpa"):
            nibbles = lowered[: -len(".ip6.arpa")].split(".")
            if len(nibbles) != 32:
                return None
            digits = "".join(reversed(nibbles))
            groups = ":".join(digits[index : index + 4] for index in range(0, 32, 4))
            self.stats["IPv6"] += 1
            if self.options.redact:
                return REDACTION_PLACEHOLDERS["Ptr"], "Ptr"
            return self.mapping.token("IPv6", normalize_ipv6(groups)) + ".ip6.arpa", "Ptr"
        return None

    def _replace_ipv6(self, value: str) -> tuple[str, str] | None:
        lowered = value.lower()
        if self.options.keep_private_ip and (
            lowered == "::1" or lowered.startswith("fe80") or lowered.startswith("fc") or lowered.startswith("fd")
        ):
            return None
        self.stats["IPv6"] += 1
        if self.options.redact:
            return REDACTION_PLACEHOLDERS["IPv6"], "IPv6"
        return self.mapping.token("IPv6", normalize_ipv6(value)), "IPv6"

    def _replace_ipv4(self, value: str) -> tuple[str, str] | None:
        if self.options.keep_private_ip and is_private_ipv4(value):
            return None
        self.stats["IPv4"] += 1
        if self.options.redact:
            return REDACTION_PLACEHOLDERS["IPv4"], "IPv4"
        key = ".".join(str(int(part)) for part in value.split("."))
        return self.mapping.token("IPv4", key), "IPv4"

    def _replace_mail(self, value: str) -> tuple[str, str] | None:
        self.stats["Mail"] += 1
        if self.options.redact:
            return REDACTION_PLACEHOLDERS["Mail"], "Mail"
        local, _, domain = value.rpartition("@")
        safe_domain = domain if self._is_kept_domain(domain) else self._domain_token(domain)
        local_token = self.mapping.token("Local", f"{local}@{domain.lower()}")
        return f"{local_token}@{safe_domain}", "Mail"

    def _replace_fqdn(self, value: str) -> tuple[str, str] | None:
        first, _, last = value.partition(".")
        # "configuration.You": two sentences glued together when a mail was
        # flattened to plain text, not a domain. Nobody writes a domain that way.
        if "." not in last and first.islower() and last[:1].isupper() and last[1:].islower():
            return None
        if value.lower() in NOT_A_DOMAIN:
            return None
        last_label = value.rpartition(".")[2].lower()
        if last_label in NON_TLD_SUFFIXES or self._is_kept_domain(value):
            return None
        self.stats["Domain"] += 1
        if self.options.redact:
            return REDACTION_PLACEHOLDERS["Domain"], "Domain"
        return self._domain_token(value), "Domain"

    def _is_kept_domain(self, domain: str) -> bool:
        value = domain.rstrip(".").lower()
        # "Never replace" on a domain covers its subdomains, like the kept domains.
        labels = value.split(".")
        if any(self.mapping.is_ignored(".".join(labels[index:])) for index in range(len(labels) - 1)):
            return True
        return any(value == kept or value.endswith("." + kept) for kept in self._keep_domains)

    def _domain_token(self, domain: str) -> str:
        value = domain.rstrip(".").lower()
        cached = self._cache.get(value)
        if cached is not None:
            return cached
        labels = value.split(".")
        base_count = 2
        if len(labels) >= 2 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
            base_count = 3
        base_count = min(base_count, len(labels))
        base_start = len(labels) - base_count
        base_token = self.mapping.token("Domain", ".".join(labels[base_start:]))
        if base_start == 0:
            self._cache[value] = base_token
            return base_token
        prefix = [
            self.mapping.token("Host", label) if self.options.anonymize_hostname else label
            for label in labels[:base_start]
        ]
        token = ".".join(prefix + [base_token])
        self._cache[value] = token
        return token

    # -- restore -----------------------------------------------------------

    def restore_line(self, line: str) -> str:
        return "".join(segment.text for segment in self.restore_segments(line))

    def restore_segments(self, line: str) -> list[Segment]:
        if self._reverse is None:
            self._reverse = self.mapping.reverse()
        parts: list[Segment] = [Segment(line)]
        for kind, regex in _RESTORE_PATTERNS:
            parts = self._apply_restore(parts, regex, kind)
        return parts

    def _apply_restore(self, parts: list[Segment], regex: re.Pattern, kind: str) -> list[Segment]:
        result: list[Segment] = []
        for segment in parts:
            if segment.category is not None:
                result.append(segment)
                continue
            position = 0
            text = segment.text
            for match in regex.finditer(text):
                value = self._resolve_token(match.group(0), kind)
                if value is None:
                    continue
                if match.start() > position:
                    result.append(Segment(text[position : match.start()]))
                result.append(Segment(value, "Restored", match.group(0)))
                position = match.end()
            if position < len(text):
                result.append(Segment(text[position:]))
        return [segment for segment in result if segment.text or segment.category]

    def _resolve_token(self, token: str, kind: str) -> str | None:
        assert self._reverse is not None
        if kind == "ptr4":
            base = re.sub(r"\.in-addr\.arpa$", "", token, flags=re.IGNORECASE)
            address = self._lookup(base, "IPv4")
            if address is None:
                return None
            return ".".join(reversed(address.split("."))) + ".in-addr.arpa"
        category = {
            "ipv4": "IPv4",
            "ipv6": "IPv6",
            "extra": "Extra",
            "person": "Person",
            "company": "Company",
            "phone": "Phone",
            "street": "Street",
            "city": "City",
            "register": "Register",
            "account": "Account",
            "domain": "Domain",
            "host": "Host",
            "local": "Local",
        }[kind]
        value = self._lookup(token, category)
        if value is None:
            return None
        if category == "Local":
            local, separator, _ = value.rpartition("@")
            return local if separator else value
        return value

    def _lookup(self, token: str, category: str) -> str | None:
        assert self._reverse is not None
        value = self._reverse[category].get(token.lower())
        if value is None:
            self.unresolved += 1
            self.unknown_tokens[token] = True
            return None
        self.restored += 1
        return value

    # -- files -------------------------------------------------------------

    def process_file(
        self,
        source: str | Path,
        target: str | Path,
        encoding: str = "auto",
        restore: bool = False,
        progress=None,
        cancelled=None,
    ) -> int:
        source = Path(source)
        target = Path(target)
        read_encoding, write_encoding = resolve_encodings(source, encoding)
        transform = self.restore_line if restore else self.process_line
        if not restore and self.options.detect_personal:
            with source.open("r", encoding=read_encoding, errors="surrogateescape", newline="") as reader:
                self.learn_lines((split_line_ending(raw)[0] for raw in reader), cancelled)
        lines = 0
        total = source.stat().st_size or 1
        seen = 0
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("r", encoding=read_encoding, errors="surrogateescape", newline="") as reader:
            with target.open("w", encoding=write_encoding, errors="surrogateescape", newline="") as writer:
                for raw in reader:
                    if cancelled is not None and cancelled():
                        raise Cancelled(f"Cancelled while writing {target.name}.")
                    content, ending = split_line_ending(raw)
                    writer.write(transform(content))
                    writer.write(ending)
                    lines += 1
                    seen += len(raw)
                    if progress is not None and lines % 2000 == 0:
                        progress(min(seen / total, 1.0))
        return lines


class Cancelled(RuntimeError):
    """Raised when a running job was cancelled by the user."""


# Besides the replacement rules the check counts hints at credentials and key
# material; those are never replaced, so only a person can judge them.
_SECRET_HINTS = (
    (
        "Secret word",
        re.compile(r"\b(?:password|passwd|secret|token|api[_ -]?key|access[_ -]?key|private[_ -]?key)\b", re.IGNORECASE),
    ),
    ("Private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)

# What the tool writes itself: tokens, redaction texts and pseudonymous addresses.
_OWN_OUTPUT = re.compile(
    r"\[[A-Za-z0-9]+-(?:\d+|ENTFERNT)\]|(?:user\d+@)?(?:host\d+\.)*kunde\d+\.tld|host\d+|user\d+",
    re.IGNORECASE,
)


def find_leaks(text: str, mapping: Mapping | None = None) -> dict[str, int]:
    """Count what in an anonymized text still looks sensitive, per kind.

    Runs the full detection over the text; with the store's mapping every name
    it already knows counts as well, and its never-replace list is honoured.
    The mapping is changed in memory and must not be saved afterwards. Only
    counts come back: a check must not print what it is meant to keep secret.
    """
    engine = Anonymizer(mapping if mapping is not None else Mapping(), Options())
    engine.learn_text(text)
    counts: dict[str, int] = {}
    for line in text.splitlines():
        for segment in engine.segments(line):
            if segment.category and not _OWN_OUTPUT.fullmatch(segment.original):
                label = CATEGORY_LABELS.get(segment.category, segment.category)
                counts[label] = counts.get(label, 0) + 1
        for label, regex in _SECRET_HINTS:
            found = len(regex.findall(line))
            if found:
                counts[label] = counts.get(label, 0) + found
    return counts


def read_text(source: str | Path, encoding: str = "auto") -> str:
    """Whole file as text; without a BOM UTF-8 is tried before CP1252."""
    source = Path(source)
    read_encoding, _ = resolve_encodings(source, encoding)
    data = source.read_bytes()
    if encoding.lower() == "auto" and read_encoding == "cp1252":
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            pass
    return data.decode(read_encoding, errors="surrogateescape")


def _term_pattern(terms: list[str]) -> re.Pattern | None:
    """Own terms are plain text: no regex knowledge needed, case does not matter."""
    parts = []
    for term in sorted({term for term in terms if term.strip()}, key=len, reverse=True):
        body = re.escape(term)
        head = r"(?<!\w)" if re.match(r"\w", term) else ""
        tail = r"(?!\w)" if re.search(r"\w$", term) else ""
        parts.append(head + body + tail)
    return re.compile("|".join(parts), re.IGNORECASE) if parts else None


def split_line_ending(raw: str) -> tuple[str, str]:
    for ending in ("\r\n", "\n", "\r"):
        if raw.endswith(ending):
            return raw[: -len(ending)], ending
    return raw, ""


ENCODING_ALIASES = {
    "ansi": "cp1252",
    "latin1": "iso-8859-1",
    "unicode": "utf-16",
    "utf8": "utf-8",
    "ascii": "ascii",
}


def resolve_encodings(source: Path, encoding: str) -> tuple[str, str]:
    """Return (read, write) codecs; 'auto' honours a BOM and falls back to CP1252."""
    name = (encoding or "auto").lower()
    if name != "auto":
        codec = ENCODING_ALIASES.get(name, name)
        return codec, codec
    with source.open("rb") as handle:
        prefix = handle.read(4)
    if prefix.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig", "utf-8-sig"
    if prefix.startswith(b"\xff\xfe") or prefix.startswith(b"\xfe\xff"):
        return "utf-16", "utf-16"
    return "cp1252", "cp1252"


def default_output_path(source: str | Path, output: str | Path | None, restore: bool = False) -> Path:
    source = Path(source)
    marker = "klartext" if restore else "anonym"
    name = f"{source.stem}.{marker}{source.suffix}"
    if not output:
        return source.parent / name
    output = Path(output)
    if output.is_dir() or str(output).endswith(("/", "\\")):
        return output / name
    return output
