"""Technical identifiers in log text: what they are and where they stand.

An entity is a normalized value of one kind, such as the IPv4 address
"203.0.113.7"; an occurrence is one place in one log event where it appears.
Rules live in a registry (`RULES`, extended with `register`), so a new kind of
identifier needs one rule and nothing else. Address, mail and domain shapes are
the ones the anonymizer uses, so investigating and masking agree on what an
address is.

Kinds differ in what they prove when two events share them:

* unique   - names one transaction: a message, a queue file, a session, a request.
             Sharing one is a direct link.
* identity - names a party: an account, an address, a device. Sharing one is a
             hint whose weight depends on how often the value appears.
* weak     - describes rather than identifies: a status, a code, a process id
             that the system reuses. Searchable, never used to link.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from dataclasses import dataclass
from typing import Callable

from .anonymize import _FQDN, _IPV4, _IPV6, _MAIL, NON_TLD_SUFFIXES, NOT_A_DOMAIN, TITLE_CASE_TLDS

KIND_LABELS = {
    "msgid": "Message-ID",
    "queue": "Queue-Datei",
    "session": "Sitzung",
    "request": "Request",
    "email": "E-Mail-Adresse",
    "account": "Konto",
    "device": "Gerät",
    "ipv4": "IPv4-Adresse",
    "ipv6": "IPv6-Adresse",
    "endpoint": "IP und Port",
    "domain": "Domain / Host",
    "host": "Rechnername",
    "url": "URL",
    "status": "Statuscode",
    "code": "Fehler-/Meldungscode",
    "pid": "Prozess / Thread",
    "port": "Port",
}

UNIQUE_KINDS = frozenset({"msgid", "queue", "session", "request"})
IDENTITY_KINDS = frozenset({"email", "account", "device", "ipv4", "ipv6", "endpoint", "domain", "host", "url"})
WEAK_KINDS = frozenset({"status", "code", "pid", "port"})
# Identities that name one party. A domain or host is shared by everybody who
# writes to it, so it is shown and searchable but never links events by itself.
LINK_KINDS = frozenset({"email", "account", "device", "ipv4", "ipv6", "endpoint"})
IP_KINDS = frozenset({"ipv4", "ipv6", "endpoint"})

# Addresses that stand for "this machine" or "nobody" link nothing.
GENERIC_IPS = frozenset({"127.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "::"})
# Mailboxes that systems send from or to on everybody's behalf.
GENERIC_LOCAL_PARTS = frozenset(
    "postmaster mdaemon mailer-daemon noreply no-reply donotreply do-not-reply root abuse daemon "
    "nobody system administrator".split()
)


@dataclass(frozen=True)
class Found:
    kind: str
    value: str  # normalized: the key two occurrences are compared by
    start: int = -1
    end: int = -1
    role: str = ""
    display: str = ""  # as written, for showing; defaults to value


@dataclass
class Rule:
    kind: str
    pattern: re.Pattern
    group: str | int = 0
    normalize: Callable[[str], str | None] = lambda value: value
    # Lower runs first; a span claimed by an earlier rule is not matched again,
    # so the address inside a Message-ID is not also counted as a mail address.
    priority: int = 100
    # A cheap test that every match needs, given the text and its lower case:
    # most log lines hold no "@", so the address patterns need not look at them.
    hint: Callable[[str, str], bool] | None = None


def _lower(value: str) -> str:
    return value.lower()



@functools.lru_cache(maxsize=1 << 16)
def normalize_ip(value: str) -> tuple[str, str] | None:
    """(kind, value); an IPv4 address written in IPv6 notation counts as IPv4."""
    value = value.strip("[]")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return "ipv4", str(address.ipv4_mapped)
    return ("ipv6" if address.version == 6 else "ipv4"), str(address)


def _msgid(value: str) -> str | None:
    value = value.strip().strip("<>").strip()
    return value if "@" in value and len(value) >= 5 else None


def _queue(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def normalize_domain(raw: str) -> str | None:
    # The anonymizer's exceptions apply here too, so both agree on what a domain
    # is: "Task 30927.Regards" and "this Feature.Mit" are glued sentences.
    first, _, last = raw.rstrip(".").partition(".")
    if "." not in last and last[:1].isupper() and last[1:].islower():
        if first.islower() or first.isdigit() or last.lower() not in TITLE_CASE_TLDS:
            return None
    value = raw.rstrip(".").lower()
    labels = value.split(".")
    if len(labels) < 2 or labels[-1] in NON_TLD_SUFFIXES or value in NOT_A_DOMAIN:
        return None
    if all(label.isdigit() for label in labels[:-1]) or labels[-1].isdigit():
        return None
    return value


_FQDN_RE = re.compile(_FQDN, re.IGNORECASE)
_DOMAIN_HINT = re.compile(r"[A-Za-z0-9-]\.[A-Za-z]")


def is_domain(text: str) -> bool:
    """Whether the whole text is a domain the address rules take as one."""
    return bool(_FQDN_RE.fullmatch(text)) and normalize_domain(text) is not None


def _url(value: str) -> str:
    return value.rstrip(".,;)\"'")


RULES: list[Rule] = [
    # A Message-ID is recognized by its label, not its shape: it looks exactly
    # like an address. "processing message <…>" is how SpamAssassin names it.
    Rule(
        "msgid",
        re.compile(
            r"(?i)(?:message[- ]?id|nachrichten-id|strmessageid|processing message)\s*[:=]?\s*"
            r"(?P<v><?[^\s<>\"]+@[^\s<>\"]+?>?)(?=[\s,;)]|$)"
        ),
        "v",
        _msgid,
        priority=10,
        hint=lambda text, low: "@" in text,
    ),
    Rule("url", re.compile(r"(?i)\bhttps?://[^\s\"'<>|]+"), 0, _url, priority=20, hint=lambda text, low: "://" in text),
    Rule("email", re.compile(_MAIL, re.IGNORECASE), 0, _lower, priority=30, hint=lambda text, low: "@" in text),
    # MDaemon queue files carry the message from conversion to delivery.
    Rule(
        "queue", re.compile(r"(?i)(?<![\w])(?:md|pd)\d{8,}\.(?:msg|raw)(?![\w])"), 0, _queue, priority=40,
        hint=lambda text, low: ".msg" in low or ".raw" in low,
    ),
    Rule(
        "domain", re.compile(_FQDN, re.IGNORECASE), 0, normalize_domain, priority=90,
        hint=lambda text, low: _DOMAIN_HINT.search(text) is not None,
    ),
]


def register(rule: Rule) -> None:
    """Add a rule for a new kind of identifier; it applies to every import that follows."""
    RULES.append(rule)
    RULES.sort(key=lambda item: item.priority)


RULES.sort(key=lambda item: item.priority)

_IPV6_RE = re.compile(_IPV6)
_IPV4_RE = re.compile(_IPV4)
# Necessary for a match, and much cheaper: every domain ends in a label, a dot
# and a letter; every IPv6 address has eight groups or "::"; every IPv4
# address has two dots around a short number.
_IPV6_HINT = re.compile(r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]")
_IPV4_HINT = re.compile(r"\d\.\d{1,3}\.\d")
_PORT = re.compile(r":(\d{1,5})(?![\d.])")
# "Chrome/120.0.0.0" in a user agent is a product version shaped like an
# address. Counted as one, every user of that browser would share it.
_PRODUCT = re.compile(r"(?<![\w.-])([A-Za-z][A-Za-z-]*)/$")


def _claimed(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(start < other_end and other_start < end for other_start, other_end in spans)


def extract(text: str) -> list[Found]:
    """Every identifier the rules find in text, each span counted once."""
    found: list[Found] = []
    spans: list[tuple[int, int]] = []

    def add(item: Found) -> None:
        found.append(item)
        if item.start >= 0:
            spans.append((item.start, item.end))

    low = text.lower()
    for rule in RULES:
        if rule.priority >= 50:
            break
        if rule.hint is not None and not rule.hint(text, low):
            continue
        for match in rule.pattern.finditer(text):
            start, end = match.span(rule.group)
            if _claimed(spans, start, end):
                continue
            value = rule.normalize(match.group(rule.group))
            if value:
                add(Found(rule.kind, value, start, end, display=match.group(rule.group)))

    # Addresses, with the port when one follows: "203.0.113.7:51744" is one
    # connection's endpoint as well as the address.
    regexes = []
    if "::" in text or _IPV6_HINT.search(text):
        regexes.append(_IPV6_RE)
    if _IPV4_HINT.search(text):
        regexes.append(_IPV4_RE)
    for regex in regexes:
        for match in regex.finditer(text):
            start, end = match.span()
            if _claimed(spans, start, end):
                continue
            normalized = normalize_ip(match.group(0))
            if normalized is None:
                continue
            kind, value = normalized
            product = _PRODUCT.search(text, max(0, start - 40), start)
            if kind == "ipv4" and product and product.group(1).lower() != "localhost":
                continue
            add(Found(kind, value, start, end, display=match.group(0)))
            # "[127.0.0.1]:56333" and "203.0.113.7:51744" both name a port.
            port = _PORT.match(text, end + 1) if text.startswith("]:", end) else _PORT.match(text, end)
            if port and 0 < int(port.group(1)) < 65536:
                endpoint = f"[{value}]:{port.group(1)}" if kind == "ipv6" else f"{value}:{port.group(1)}"
                found.append(Found("endpoint", endpoint, start, port.end(), display=text[start : port.end()]))

    for rule in RULES:
        if rule.priority < 50:
            continue
        if rule.hint is not None and not rule.hint(text, low):
            continue
        for match in rule.pattern.finditer(text):
            start, end = match.span(rule.group)
            if _claimed(spans, start, end):
                continue
            value = rule.normalize(match.group(rule.group))
            if value:
                add(Found(rule.kind, value, start, end, display=match.group(rule.group)))
    return found


def explicit(kind: str, raw: str, role: str = "") -> Found | None:
    """An identifier a parser read from a known position, normalized like the rules do."""
    raw = raw.strip()
    if not raw or raw in ("-", "(unknown)"):
        return None
    if kind in ("ipv4", "ipv6", "ip"):
        normalized = normalize_ip(raw)
        return Found(normalized[0], normalized[1], role=role, display=raw) if normalized else None
    if kind == "account":
        # A login name that is a mail address is that address; otherwise an account.
        if re.fullmatch(_MAIL, raw, re.IGNORECASE):
            return Found("email", raw.lower(), role=role or "account", display=raw)
        return Found("account", raw.lower(), role=role, display=raw)
    if kind == "email":
        return Found("email", raw.lower(), role=role, display=raw) if "@" in raw else None
    if kind == "msgid":
        value = _msgid(raw)
        return Found("msgid", value, role=role, display=raw) if value else None
    if kind == "queue":
        return Found("queue", _queue(raw), role=role, display=raw)
    if kind == "domain":
        value = normalize_domain(raw)
        return Found("domain", value, role=role, display=raw) if value else None
    if kind == "host":
        return Found("host", raw.lower(), role=role, display=raw)
    return Found(kind, raw, role=role, display=raw)


def is_generic(kind: str, value: str) -> bool:
    """Values that stand for the system itself rather than a party."""
    if kind in ("ipv4", "ipv6"):
        return value in GENERIC_IPS or value.startswith("127.")
    if kind == "endpoint":
        return value.split(":")[0] in GENERIC_IPS or value.startswith("127.")
    if kind == "email":
        return value.split("@", 1)[0] in GENERIC_LOCAL_PARTS
    if kind == "account":
        return value in GENERIC_LOCAL_PARTS
    return False
