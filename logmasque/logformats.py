"""Log formats: line structure, timestamps and what a line or block reports.

A format turns the lines of one file into events. An event carries the time as
written, the original text, a type such as "auth.ok", a severity, and the
context it belongs to - a session, a request, a processing block. The formats
in FORMATS are tried on the first lines of a file; the one that recognizes most
of them parses it, and the generic format takes everything else, reading at
least the timestamps and leaving entity recognition to the investigation.

The MDaemon rules below were derived from real MDaemon 26 logs: the event log
layout with its START headers and "----------" delimiters, IMAP sessions that
are written in partial transcripts, processing blocks of the filters, the
compact component logs, and the access and request logs of the web services.
A new product gets its own Format subclass and is added to FORMATS.
"""

from __future__ import annotations

import codecs
import email.utils
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Callable, Iterable, Iterator

from . import entities
from .entities import Found

DETAIL, INFO, WARNING, ERROR = 0, 1, 2, 3
SEVERITY_LABELS = {DETAIL: "Detail", INFO: "Info", WARNING: "Warnung", ERROR: "Fehler"}

ETYPE_LABELS = {
    "line": "Logzeile",
    "log.header": "Logkopf",
    "log.open": "Log begonnen",
    "log.close": "Log beendet",
    "log.marker": "Strukturzeile",
    "service.stop": "Dienst beendet",
    "service.start": "Dienst gestartet",
    "session.start": "Sitzung beginnt",
    "session.end": "Sitzung beendet",
    "session.timeout": "Sitzung abgelaufen",
    "conn.accept": "Verbindung angenommen",
    "conn.closed": "Verbindung getrennt",
    "geo.location": "Länderfilter",
    "tls.ok": "TLS ausgehandelt",
    "tls.error": "TLS-Fehler",
    "auth.attempt": "Anmeldung versucht",
    "auth.ok": "Anmeldung erfolgreich",
    "auth.failed": "Anmeldung fehlgeschlagen",
    "proto": "Protokollzeile",
    "proto.error": "Protokollfehler",
    "av.scan": "Virenprüfung",
    "filter.scan": "Inhaltsfilter",
    "spam.scan": "Spamprüfung",
    "spam.learn": "Bayes-Lernen",
    "dkim.sign": "DKIM-Signatur",
    "dkim.verify": "DKIM-Prüfung",
    "raw.convert": "Nachricht umgewandelt",
    "pgp.process": "MDPGP-Verarbeitung",
    "spamd.conn": "Spamd-Verbindung",
    "spamd.process": "Spamd prüft Nachricht",
    "spamd.result": "Spamd-Ergebnis",
    "http.request": "HTTP-Anfrage",
    "http.error": "HTTP-Fehler",
    "http.challenge": "Anmeldeaufforderung (401)",
    "http.response": "HTTP-Antwort",
    "activesync.request": "ActiveSync-Anfrage",
    "screen.summary": "Screening-Statistik",
    "plugin": "Plugin",
}

MONTHS = {name: number for number, name in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}
_WEEKDAY = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
_MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
LEVELS = {
    "trace": DETAIL, "debug": DETAIL, "d": DETAIL, "t": DETAIL,
    "info": INFO, "notice": INFO, "i": INFO, "g": INFO,
    "warn": WARNING, "warning": WARNING, "w": WARNING,
    "error": ERROR, "err": ERROR, "fatal": ERROR, "critical": ERROR, "e": ERROR, "f": ERROR,
}


@dataclass
class Event:
    line_start: int
    line_end: int
    text: str
    wall: datetime | None = None  # as written, without a zone
    offset: int | None = None  # minutes east of UTC, when the line states it
    ts_flag: str = "local"  # exact | local | inherited | none | ambiguous | invalid
    etype: str = "line"
    severity: int = INFO
    context: str | None = None  # groups the events of one session, request or block
    context_kind: str = ""  # "session" or "request": also searchable as an entity
    context_label: str = ""
    ids: list[Found] = field(default_factory=list)  # identifiers the format read from known positions
    segment: int = 0  # restarts of the logging service; ids restart with them


@dataclass
class Hints:
    name: str = ""
    file_date: date | None = None


def wall_time(year, month, day, hour, minute, second, fraction="") -> datetime | None:
    try:
        micro = int((fraction or "0")[:6].ljust(6, "0"))
        return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), micro)
    except (TypeError, ValueError):
        return None


def offset_minutes(text: str) -> int | None:
    match = re.fullmatch(r"([+-])(\d\d):?(\d\d)", text.strip())
    if not match:
        return 0 if text.strip() == "Z" else None
    minutes = int(match.group(2)) * 60 + int(match.group(3))
    return minutes if match.group(1) == "+" else -minutes


# -- reading -------------------------------------------------------------------


def detect_encoding(path: str | Path) -> str:
    """UTF-8 when the start of the file decodes as UTF-8, Windows-1252 otherwise."""
    with open(path, "rb") as handle:
        head = handle.read(1 << 20)
    return encoding_of(head)


def encoding_of(head: bytes) -> str:
    """The encoding of a file, judged by its first bytes."""
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16"
    try:
        head.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError as error:
        # A character cut at the end of the sample is no evidence against UTF-8.
        return "utf-8" if error.start >= len(head) - 3 else "cp1252"


def read_lines(path: str | Path, encoding: str) -> Iterator[str]:
    """Lines without their endings; the file is only ever opened for reading."""
    with open(path, "r", encoding=encoding, errors="replace", newline="") as handle:
        for raw in handle:
            yield raw.rstrip("\r\n")


_EOL = re.compile(rb"\r\n|\n|\r")


def binary_lines(encoding: str) -> bool:
    """Whether lines of this encoding can be found in the bytes: not so in UTF-16."""
    return not encoding.lower().replace("_", "-").startswith("utf-16")


def bom_of(encoding: str) -> bytes:
    return codecs.BOM_UTF8 if encoding.lower().replace("_", "-") == "utf-8-sig" else b""


def read_raw_lines(
    handle, offset: int = 0, hasher=None, chunk_size: int = 1 << 20, bom: bytes = b""
) -> Iterator[tuple[int, bytes]]:
    """(byte offset, line without its ending) from offset on, for an encoding where binary_lines holds.

    Line ends are those of read_lines - "\r\n", "\n" and a lone "\r" - so line
    numbers agree. A byte order mark at the start of the file is no part of the
    first line. A hasher sees every byte read, which hashes the whole file in
    the same pass when reading starts at 0.
    """
    handle.seek(offset)
    pending = b""
    position = offset
    first = offset == 0 and bool(bom)
    while True:
        chunk = handle.read(chunk_size)
        if not chunk:
            break
        if hasher is not None:
            hasher.update(chunk)
        data = pending + chunk
        if first:
            if len(data) < len(bom) and bom.startswith(data):
                pending = data
                continue
            first = False
            if data.startswith(bom):
                data = data[len(bom):]
                position += len(bom)
        start = 0
        for match in _EOL.finditer(data):
            if match.end() == len(data) and match.end() - match.start() == 1 and data[match.start()] == 13:
                break  # a "\r" at the end may be the first half of "\r\n"
            yield position + start, data[start:match.start()]
            start = match.end()
        pending = data[start:]
        position += start
    if pending:
        yield position, pending[:-1] if pending.endswith(b"\r") else pending


# -- rules: what a message says --------------------------------------------------


@dataclass
class LineRule:
    pattern: re.Pattern
    etype: str
    severity: int = INFO
    # group name -> (entity kind, role); kinds as in entities.explicit
    groups: dict = field(default_factory=dict)
    # refines severity or type from the match, e.g. infected attachments > 0
    refine: Callable[[re.Match], tuple[str, int] | None] | None = None


def _rule(pattern: str, etype: str, severity: int = INFO, refine=None, **groups) -> LineRule:
    return LineRule(re.compile(pattern), etype, severity, groups, refine)


def _count_above_zero(etype: str, severity: int):
    return lambda match: (etype, severity) if int(match.group("n")) > 0 else None


def _spam_verdict(match: re.Match):
    return ("spam.scan", WARNING) if float(match.group("score")) >= float(match.group("required")) else None


def _dkim_result(match: re.Match):
    result = match.group("result").lower()
    if result.startswith("0") or "ok" in result or "pass" in result or result.startswith("neutral"):
        return None
    return None if "none" in result else (None, WARNING)


def _http_status(match: re.Match):
    status = int(match.group("status"))
    return (None, ERROR) if status >= 500 else (None, WARNING) if status in (401, 403, 407) else None


# Derived from MDaemon 26 logs. The first rule that matches a message decides.
MDAEMON_RULES = [
    _rule(r"^-{10}$", "log.marker", DETAIL),
    _rule(r"^Session (?P<session>\d+); child \d+", "session.start"),
    _rule(
        r"^Accepting (?P<proto>\w+) connection from (?P<client>\[?[0-9A-Fa-f.:]+?\]?):(?P<cport>\d+) "
        r"to (?P<server>\[?[0-9A-Fa-f.:]+?\]?):(?P<sport>\d+)",
        "conn.accept", client=("ip", "client"), server=("ip", "server"),
    ),
    _rule(r"^Laut L.nder-Filter geht die Verbindung von .+ aus", "geo.location", DETAIL),
    _rule(r"^SSL-Protokollverhandlung erfolgreich", "tls.ok", DETAIL),
    _rule(r"^SSL negotiation error: (?P<code>-?\d+)", "tls.error", WARNING, code=("code", "")),
    _rule(r"^Echtheitsbest.tigung f.r (?P<account>\S+) wird durchgef.hrt", "auth.attempt", account=("account", "")),
    _rule(r"^Authenticated as (?P<account>\S+)", "auth.ok", account=("account", "")),
    _rule(r"^\w+ session complete", "session.end"),
    _rule(r"^\w+ session terminated", "session.end"),
    _rule(r"^Socket connection closed by the other side", "conn.closed"),
    _rule(r"^--> \* BYE connection timed out", "session.timeout", WARNING),
    _rule(r"^--> \S+ (?:NO|BAD) ", "proto.error", WARNING),
    _rule(r"^(?:<--|-->) ", "proto", DETAIL),
    _rule(r"^Sending \w+ response \(not logged\)", "proto", DETAIL),
    # Processing blocks of the filters; a block reports the queue file first.
    _rule(r"^MDaemon AntiVirus processing (?P<file>\S+?)\.{3}$", "av.scan"),
    _rule(r"^Content Filter processing (?P<file>\S+?)\.{3}$", "filter.scan"),
    _rule(r"^Spam Filter processing (?P<file>\S+?)\.{3}$", "spam.scan"),
    _rule(r"^Performing DKIM signing", "dkim.sign"),
    _rule(r"^Performing DKIM verification", "dkim.verify"),
    _rule(r"^<(?P<file>[^>]+\.raw)> wird umgewandelt", "raw.convert"),
    _rule(r"^Umwandlung abgeschlossen \((?P<file>\S+) erstellt\)", "raw.convert"),
    _rule(r"^Verarbeite (?P<file>\S+)", "pgp.process"),
    _rule(r"^Performing Bayesian learning", "spam.learn"),
    _rule(r"^\* Message return-path: (?P<rp>\S+)", "line", DETAIL, rp=("email", "return-path")),
    _rule(r"^\* Message from: (?P<sender>\S+)", "line", DETAIL, sender=("email", "from")),
    _rule(r"^\* Message to: (?P<rcpt>\S+)", "line", DETAIL, rcpt=("email", "to")),
    _rule(r"^Von: (?P<sender>\S+@\S+)$", "line", DETAIL, sender=("email", "from")),
    _rule(r"^An: (?P<rcpt>\S+@\S+)$", "line", DETAIL, rcpt=("email", "to")),
    _rule(r"^\* Total attachments infected\s*: (?P<n>\d+)", "line", DETAIL, _count_above_zero("av.scan", ERROR)),
    _rule(r"^\* Matched (?P<n>\d+) of \d+ active rules", "line", DETAIL, _count_above_zero("filter.scan", WARNING)),
    _rule(r"^(?P<score>-?\d+\.\d+) points, (?P<required>-?\d+\.\d+) required", "line", DETAIL, _spam_verdict),
    _rule(r"^\*\s+Result: (?P<result>.+)", "line", DETAIL, _dkim_result),
    _rule(r"^\*\s+(?:Parser: )?str(?:Authenticated|Working)User\S*=(?P<account>\S+)", "line", DETAIL, account=("account", "")),
    _rule(r"thread-ID: (?P<pid>\d+)", "line", DETAIL, pid=("pid", "thread")),
    _rule(r"^Host header and IP on this request: (?P<host>\S+) \| (?P<client>\S+)", "http.request", client=("ip", "client")),
    _rule(r"Beginn der Protokolldatei|Opening Log", "log.open"),
    _rule(r"Ende der Protokolldatei|Closing Log|Protokolldatei wird archiviert", "log.close"),
    _rule(r"Plugin wird installiert|plug-in loaded", "plugin"),
    # SpamAssassin's own lines inside MDSpamD.log: "Oct 22 00:00:17.143 [-1724] info: spamd: …"
    _rule(
        rf"^{_MONTH} +\d+ [\d:.]+ \[(?P<pid>-?\d+)\] (?P<level>\w+): spamd: connection from (?P<host>\S+) "
        r"\[(?P<client>[^\]]+)\]:\d+ to port \d+",
        "spamd.conn", DETAIL, pid=("pid", "spamd"), host=("host", "client"), client=("ip", "client"),
    ),
    _rule(
        rf"^{_MONTH} +\d+ [\d:.]+ \[(?P<pid>-?\d+)\] (?P<level>\w+): spamd: processing message ",
        "spamd.process", pid=("pid", "spamd"),
    ),
    _rule(
        rf"^{_MONTH} +\d+ [\d:.]+ \[(?P<pid>-?\d+)\] (?P<level>\w+): spamd: (?:clean message|identified spam|result:)",
        "spamd.result", pid=("pid", "spamd"),
    ),
    _rule(rf"^{_MONTH} +\d+ [\d:.]+ \[(?P<pid>-?\d+)\] (?P<level>warn|error)\w*:", "line", WARNING, pid=("pid", "spamd")),
]

# Compact component logs (ActiveSync, Dynamic Screening, …).
COMPONENT_RULES = [
    _rule(
        r"^Connection: IP:(?P<client>\S+) SRV:(?P<srv>\S+) RM:\w+.*?QS:(?P<qs>\S+)",
        "activesync.request", client=("ip", "client"), srv=("domain", "server"),
    ),
    _rule(r"^Authenticated: (?P<account>\S+)", "auth.ok", account=("account", "")),
    _rule(r"^Sending HTTP/(?P<status>\d{3})", "http.response", INFO, _http_status),
    _rule(r"^Sync session terminating", "session.end", DETAIL),
    _rule(r"^Summary:\s+(?P<what>[\w ]+?): (?P<n>\d+)$", "screen.summary", DETAIL),
]

# Request logs of the web services (WebDAV, WebAdmin, XMPP, …).
REQUEST_RULES = [
    _rule(r"^Connection: (?P<client>[0-9A-Fa-f.:]+) Method:(?P<method>\w+)", "http.request", client=("ip", "client")),
    _rule(r"^Authenticate: (?P<account>\S+) successfully authenticated", "auth.ok", account=("account", "")),
    _rule(r"^Authenticate: Username = (?P<account>\S+)", "auth.attempt", DETAIL, account=("account", "")),
    # The first request of a client goes without credentials; the 401 asks for them.
    _rule(r"^Send HTTP Error: 401 - No 'Authorization", "http.challenge", DETAIL),
    _rule(r"^Send HTTP Error: (?P<status>\d{3}) ", "http.error", INFO, _http_status),
]


_LITERAL = re.compile(r"\\([^A-Za-z0-9])|([A-Za-z0-9 <>:'\"_=-])")


def _first_chars(source: str) -> frozenset[str] | None:
    """The characters a message must start with for the pattern to match, if it is anchored on a literal."""
    if not source.startswith("^"):
        return None
    rest = source[1:]
    alternatives = [rest]
    group = re.match(r"\(\?:((?:[^()|]+\|)*[^()|]+)\)", rest)
    if group:
        alternatives = group.group(1).split("|")
    chars = set()
    for alternative in alternatives:
        literal = _LITERAL.match(alternative)
        if not literal:
            return None
        chars.add(literal.group(1) or literal.group(2))
    return frozenset(chars)


_DISPATCH: dict[tuple[int, int], tuple[dict[str, list[LineRule]], list[LineRule]]] = {}


def _candidates(rules: list[LineRule], first: str) -> list[LineRule]:
    """The rules that can match a message starting with this character, in their order."""
    key = (id(rules), len(rules))
    table = _DISPATCH.get(key)
    if table is None:
        keyed = [(rule, _first_chars(rule.pattern.pattern)) for rule in rules]
        chars = set().union(*(found for _, found in keyed if found))
        by_char = {char: [rule for rule, found in keyed if found is None or char in found] for char in chars}
        table = by_char, [rule for rule, found in keyed if found is None]
        _DISPATCH[key] = table
    by_char, unanchored = table
    return by_char.get(first, unanchored)


def apply_rules(rules: list[LineRule], message: str) -> tuple[str, int, list[Found]]:
    # Most rules are anchored on a literal: only those that can match the first
    # character are tried. The first rule that matches still decides.
    for rule in _candidates(rules, message[:1]):
        match = rule.pattern.search(message)
        if not match:
            continue
        etype, severity = rule.etype, rule.severity
        if rule.refine is not None:
            refined = rule.refine(match)
            if refined is not None:
                etype = refined[0] or etype
                severity = refined[1]
        level = match.groupdict().get("level")
        if level and LEVELS.get(level.lower(), INFO) > severity:
            severity = LEVELS[level.lower()]
        found: list[Found] = []
        for group, (kind, role) in rule.groups.items():
            raw = match.groupdict().get(group)
            item = entities.explicit(kind, raw or "", role) if raw else None
            if item is not None:
                found.append(item)
        if "qs" in match.groupdict():
            found.extend(_query_string(match.group("qs")))
        return etype, severity, found
    return "line", INFO, []


def _query_string(text: str) -> list[Found]:
    found: list[Found] = []
    for part in text.split("&"):
        key, _, value = part.partition("=")
        key = key.lower()
        if key == "user":
            item = entities.explicit("account", value)
        elif key == "deviceid":
            item = entities.explicit("device", value)
        else:
            item = None
        if item is not None:
            found.append(item)
    return found


# -- formats -------------------------------------------------------------------


class Format:
    name = "generic"
    label = "Allgemeines Textlog"

    def recognizes(self, line: str) -> bool:
        return False

    def score(self, sample: list[str]) -> float:
        if not sample:
            return 0.0
        return sum(1 for line in sample if self.recognizes(line)) / len(sample)

    def parse(self, lines: Iterable[str], hints: Hints) -> Iterator[Event]:
        raise NotImplementedError

    # A line without a timestamp continues the event before it when it is
    # indented, and otherwise stands alone with the time of its predecessor.
    @staticmethod
    def _line_events(lines: Iterable[str], parse_line) -> Iterator[Event]:
        pending: Event | None = None
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            event = parse_line(line, number)
            if event is None:
                if pending is not None and line[:1].isspace():
                    pending.text += "\n" + line
                    pending.line_end = number
                    continue
                event = Event(
                    number, number, line,
                    wall=pending.wall if pending else None,
                    offset=pending.offset if pending else None,
                    ts_flag="inherited" if pending and pending.wall else "none",
                    segment=pending.segment if pending else 0,
                )
            if pending is not None:
                yield pending
            pending = event
        if pending is not None:
            yield pending


class MDaemonEventLog(Format):
    """The classic MDaemon log: "Wed 2026-10-21 00:01:00.971: text".

    Filters write processing blocks closed by "----------"; protocol logs write
    sessions, long ones in partial transcripts whose continuation starts with
    the last line of the previous part. Session numbers restart with every
    "START Event Log" header, so contexts carry the restart they belong to.
    """

    name = "mdaemon"
    label = "MDaemon-Ereignisprotokoll"
    LINE = re.compile(
        rf"^﻿?(?:{_WEEKDAY} )?(\d{{4}})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)(?:\.(\d{{1,6}}))?: ?(.*)$"
    )
    HEADER = re.compile(r"^(?:START Event Log|-{20,}|Event Time/Date|Server Shutdown)")
    CODE = re.compile(r"^(\d\d): ")
    LEVEL_ID = re.compile(r"^([GIDEWT]) \[([0-9A-Fa-f]{8})\] ")
    JOB = re.compile(r"^\[(-?\d{3,})\] ")
    REQUEST = re.compile(r"^\{([0-9A-Fa-f]{6,})\} ")
    SESSION = re.compile(r"^Session (\d+); child \d+")
    SHUTDOWN = re.compile(r"^Server Shutdown\s+(.+)$")
    BLOCK_LIMIT = 400

    def __init__(self) -> None:
        self.detected_offset: int | None = None

    def recognizes(self, line: str) -> bool:
        return bool(self.LINE.match(line) or self.HEADER.match(line))

    def parse(self, lines: Iterable[str], hints: Hints) -> Iterator[Event]:
        segment = 0
        buffer: list[tuple] = []  # (number, line, wall, message, context, label, kind, severity_hint, last line)
        chunk: list[tuple] | None = None
        tails: dict[str, str] = {}  # last line of a partial transcript -> its session
        last_wall: datetime | None = None

        def line_event(item, context=None, kind="", label="") -> Event:
            number, line, wall, message, own_context, own_label, own_kind, level, end = item
            etype, severity, ids = apply_rules(MDAEMON_RULES, message)
            if level is not None and level > severity:
                severity = level
            return Event(
                number, end, line, wall=wall, ts_flag="local" if wall else "invalid",
                etype=etype, severity=severity, ids=ids, segment=segment,
                context=context or own_context, context_kind=kind or own_kind, context_label=label or own_label,
            )

        def session_events(items, session) -> Iterator[Event]:
            context = f"session:{segment}:{session}" if session else f"chunk:{segment}:{items[0][0]}"
            label = f"Sitzung {session}" if session else ""
            for item in items:
                yield line_event(item, context, "session" if session else "", label)

        def close(items, delimited: bool) -> Iterator[Event]:
            if not items:
                return
            session = next((m.group(1) for m in (self.SESSION.match(i[3]) for i in items) if m), None)
            continued = tails.get(items[0][1])
            if session or continued:
                if continued and not session:
                    items = items[1:]  # the first line repeats the end of the previous part
                    session = continued
                if items:
                    yield from session_events(items, session)
                return
            if delimited and len(items) >= 2:
                yield self._block(items, segment)
                return
            for item in items:
                yield line_event(item)

        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            match = self.LINE.match(line)
            if match is None:
                if line.startswith("START Event Log"):
                    yield from close(buffer, False)
                    buffer = []
                    segment += 1
                    yield Event(number, number, line, ts_flag="none", etype="log.header", severity=DETAIL, segment=segment)
                    continue
                shutdown = self.SHUTDOWN.match(line)
                if shutdown:
                    when = _rfc2822(shutdown.group(1))
                    if when is not None:
                        self.detected_offset = when[1]
                    yield Event(
                        number, number, line, wall=when[0] if when else None, offset=when[1] if when else None,
                        ts_flag="exact" if when else "none", etype="service.stop", segment=segment,
                    )
                    continue
                if self.HEADER.match(line):
                    continue
                # A line without a timestamp belongs to the line before it.
                target = chunk if chunk is not None else buffer
                if target:
                    previous = target[-1]
                    target[-1] = (previous[0], previous[1] + "\n" + line, *previous[2:8], number)
                else:
                    yield Event(number, number, line, wall=last_wall, ts_flag="inherited" if last_wall else "none", segment=segment)
                continue

            wall = wall_time(*match.groups()[:7])
            last_wall = wall or last_wall
            message = match.group(8)
            context = label = kind = ""
            level = None
            code = self.CODE.match(message)
            if code:
                message = message[code.end():]
            level_id = self.LEVEL_ID.match(message)
            if level_id:
                level = LEVELS.get(level_id.group(1).lower())
                context = f"req:{segment}:{level_id.group(2)}"
                label, kind = f"Vorgang {level_id.group(2)}", "request"
                message = message[level_id.end():]
            for pattern, prefix, title in ((self.JOB, "job", "Vorgang"), (self.REQUEST, "req", "Request")):
                found = pattern.match(message)
                if found:
                    context = f"{prefix}:{segment}:{found.group(1)}"
                    label, kind = f"{title} {found.group(1)}", "request"
                    message = message[found.end():]
                    break
            item = (number, line, wall, message, context or None, label, kind, level, number)

            if message.startswith("--------- Partial transcript"):
                yield from close(buffer, False)
                buffer = []
                chunk = []
                yield Event(number, number, line, wall=wall, etype="log.marker", severity=DETAIL, segment=segment)
                continue
            if message.startswith("---------- End partial transcript"):
                if chunk:
                    session = next((m.group(1) for m in (self.SESSION.match(i[3]) for i in chunk) if m), None)
                    continued = tails.get(chunk[0][1])
                    if continued and not session:
                        chunk = chunk[1:]
                        session = continued
                    if session and chunk:
                        tails[chunk[-1][1]] = session
                    if chunk:
                        yield from session_events(chunk, session)
                chunk = None
                yield Event(number, number, line, wall=wall, etype="log.marker", severity=DETAIL, segment=segment)
                continue
            if chunk is not None:
                chunk.append(item)
                continue
            if "Beginn der Protokolldatei" in message:
                yield from close(buffer, False)
                buffer = []
                segment += 1
            buffer.append(item)
            if message.strip() == "----------":
                yield from close(buffer, True)
                buffer = []
            elif len(buffer) >= self.BLOCK_LIMIT:
                yield from close(buffer[:-1], False)
                buffer = buffer[-1:]
        if chunk:
            yield from close(chunk, False)
        yield from close(buffer, False)

    def _block(self, items: list[tuple], segment: int) -> Event:
        """One event for a processing block: what was processed and what came of it."""
        etype, severity, ids = "line", DETAIL, []
        for item in items:
            line_type, line_severity, found = apply_rules(MDAEMON_RULES, item[3])
            if etype == "line" and line_type not in ("line", "proto"):
                etype = line_type
            elif line_type not in ("line", "proto") and line_severity > INFO:
                etype = line_type
            severity = max(severity, line_severity)
            ids.extend(found)
        first = items[0]
        return Event(
            first[0], items[-1][8], "\n".join(item[1] for item in items),
            wall=first[2], ts_flag="local" if first[2] else "none",
            etype=etype, severity=max(severity, INFO), ids=ids, segment=segment,
            context=f"block:{segment}:{first[0]}",
        )


def _rfc2822(text: str) -> tuple[datetime, int] | None:
    try:
        parsed = email.utils.parsedate_to_datetime(text.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None or parsed.utcoffset() is None:
        return None
    return parsed.replace(tzinfo=None), int(parsed.utcoffset().total_seconds() // 60)


class ComponentLog(Format):
    """MDaemon component logs: "261021 044345274 I [0002B7C1] 0x41330080 text".

    Date as YYMMDD, time as HHMMSS plus milliseconds, a level letter, the id of
    the request or worker in brackets and a message code.
    """

    name = "mdaemon-component"
    label = "MDaemon-Komponentenlog"
    LINE = re.compile(r"^(\d\d)(\d\d)(\d\d) (\d\d)(\d\d)(\d\d)(\d{3}) ([A-Z]) \[([0-9A-Fa-f]{4,8})\] (?:(0x[0-9A-Fa-f]{8}) )?(.*)$")

    def recognizes(self, line: str) -> bool:
        return bool(self.LINE.match(line))

    def parse(self, lines: Iterable[str], hints: Hints) -> Iterator[Event]:
        def parse_line(line: str, number: int) -> Event | None:
            match = self.LINE.match(line)
            if not match:
                return None
            yy, mm, dd, hh, mi, ss, ms, level, worker, code, message = match.groups()
            wall = wall_time(2000 + int(yy), mm, dd, hh, mi, ss, ms)
            flag = "local" if wall else "invalid"
            if wall and hints.file_date and wall.date() != hints.file_date and abs((wall.date() - hints.file_date).days) > 1:
                flag = "ambiguous"
            etype, severity, ids = apply_rules(COMPONENT_RULES, message)
            # The level letter decides for plain lines; for a recognized event it
            # can only raise the severity (a warning), never hide it as debug.
            level_severity = LEVELS.get(level.lower(), INFO)
            severity = level_severity if etype == "line" else max(severity, level_severity if level_severity >= WARNING else severity)
            if code:
                ids.append(Found("code", code.lower(), role="message"))
            return Event(
                number, number, line, wall=wall, ts_flag=flag, etype=etype, severity=severity, ids=ids,
                context=f"req:0:{worker}", context_kind="request", context_label=f"Vorgang {worker}",
            )

        return self._line_events(lines, parse_line)


class BracketLog(Format):
    """"[Wed 2026-10-21 15:28:00] INFO, [CQBWHWRBDVZPMM] text" (WebDAV, WebAdmin, XMPP, …)."""

    name = "bracket"
    label = "Log mit [Zeitstempel]"
    LINE = re.compile(
        rf"^\[(?:{_WEEKDAY} )?(\d{{4}})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:[.,](\d{{1,6}}))?\] ?(.*)$"
    )
    LEVEL = re.compile(r"^(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|FATAL|CRITICAL),? ", re.IGNORECASE)
    REQUEST = re.compile(r"^\[([A-Z0-9]{8,})\] ")

    def recognizes(self, line: str) -> bool:
        return bool(self.LINE.match(line))

    def parse(self, lines: Iterable[str], hints: Hints) -> Iterator[Event]:
        def parse_line(line: str, number: int) -> Event | None:
            match = self.LINE.match(line)
            if not match:
                return None
            wall = wall_time(*match.groups()[:7])
            message = match.group(8)
            severity = INFO
            level = self.LEVEL.match(message)
            if level:
                severity = LEVELS.get(level.group(1).lower(), INFO)
                message = message[level.end():]
            context = label = kind = ""
            request = self.REQUEST.match(message)
            if request:
                context, label, kind = f"req:0:{request.group(1)}", f"Request {request.group(1)}", "request"
                message = message[request.end():]
            etype, rule_severity, ids = apply_rules(REQUEST_RULES, message)
            if etype == "line":
                etype, rule_severity, ids = apply_rules(MDAEMON_RULES, message)
            return Event(
                number, number, line, wall=wall, ts_flag="local" if wall else "invalid",
                etype=etype, severity=max(severity, rule_severity), ids=ids,
                context=context or None, context_kind=kind, context_label=label,
            )

        return self._line_events(lines, parse_line)


class AccessLog(Format):
    """Web server access lines: 'client - user 21/Oct/2026:00:00:33 +0200 "GET / HTTP/1.1" 200 11345'."""

    name = "access"
    label = "HTTP-Zugriffslog"
    LINE = re.compile(
        r'^(?P<client>\S+) (?P<ident>\S+) (?P<user>\S+) \[?(?P<d>\d\d)/(?P<mon>\w{3})/(?P<y>\d{4}):(?P<H>\d\d):'
        r'(?P<M>\d\d):(?P<S>\d\d) (?P<zone>[+-]\d{4})\]? "(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<size>\S+)'
    )

    def recognizes(self, line: str) -> bool:
        return bool(self.LINE.match(line))

    def parse(self, lines: Iterable[str], hints: Hints) -> Iterator[Event]:
        def parse_line(line: str, number: int) -> Event | None:
            match = self.LINE.match(line)
            if not match:
                return None
            month = MONTHS.get(match.group("mon").lower())
            wall = wall_time(match.group("y"), month, match.group("d"), match.group("H"), match.group("M"), match.group("S"))
            ids = [item for item in (
                entities.explicit("ip", match.group("client"), "client"),
                entities.explicit("account", match.group("user")) if match.group("user") != "-" else None,
            ) if item is not None]
            severity = INFO
            if match.group("status") != "-":
                status = int(match.group("status"))
                ids.append(Found("status", f"HTTP {status}"))
                severity = ERROR if status >= 500 else WARNING if status in (401, 403, 407) else INFO
            return Event(
                number, number, line, wall=wall, offset=offset_minutes(match.group("zone")),
                ts_flag="exact" if wall else "invalid", etype="http.request", severity=severity, ids=ids,
            )

        return self._line_events(lines, parse_line)


class PipeLog(Format):
    """"2026-10-21 15:40:43 | WARNING | 404 Not Found: GET /x from ::ffff:203.0.113.7" (RTC server)."""

    name = "pipe"
    label = "Log mit Spaltentrennern"
    LINE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:[.,](\d{1,6}))? \| (\w+) \| (.*)$")
    REQUEST = re.compile(r"^(?P<status>\d{3}) [^:]*: (?P<method>[A-Z]+) (?P<path>\S+) from (?P<client>\S+)")

    def recognizes(self, line: str) -> bool:
        return bool(self.LINE.match(line))

    def parse(self, lines: Iterable[str], hints: Hints) -> Iterator[Event]:
        def parse_line(line: str, number: int) -> Event | None:
            match = self.LINE.match(line)
            if not match:
                return None
            wall = wall_time(*match.groups()[:7])
            severity = LEVELS.get(match.group(8).lower(), INFO)
            message = match.group(9)
            etype, ids = "line", []
            request = self.REQUEST.match(message)
            if request:
                etype = "http.request"
                client = entities.explicit("ip", request.group("client"), "client")
                ids = [item for item in (client, Found("status", f"HTTP {request.group('status')}")) if item]
            return Event(number, number, line, wall=wall, ts_flag="local" if wall else "invalid", etype=etype,
                         severity=severity, ids=ids)

        return self._line_events(lines, parse_line)


class CtimeLog(Format):
    """"Wed Oct 21 00:00:00 2026 -> text" (ClamAV daemon)."""

    name = "ctime"
    label = "Log mit ctime-Zeitstempel"
    LINE = re.compile(rf"^{_WEEKDAY} ({_MONTH}) ([ \d]\d) (\d\d):(\d\d):(\d\d) (\d{{4}}) -> (.*)$")

    def recognizes(self, line: str) -> bool:
        return bool(self.LINE.match(line))

    def parse(self, lines: Iterable[str], hints: Hints) -> Iterator[Event]:
        def parse_line(line: str, number: int) -> Event | None:
            match = self.LINE.match(line)
            if not match:
                return None
            month, day, hour, minute, second, year, message = match.groups()
            wall = wall_time(year, MONTHS[month.lower()], day.strip(), hour, minute, second)
            severity = WARNING if re.search(r"(?i)\b(?:warning|error|failed)\b", message) else INFO
            return Event(number, number, line, wall=wall, ts_flag="local" if wall else "invalid", severity=severity)

        return self._line_events(lines, parse_line)


class GenericLog(Format):
    """Any text log: a timestamp at the start of a line opens an event."""

    name = "generic"
    label = "Allgemeines Textlog"
    PATTERNS = (
        # 2026-10-21T15:28:00.123+02:00, 2026-10-21 15:28:00,123, [2026-10-21 15:28:00]
        (re.compile(
            r"^\[?(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d{1,9}))?[ ]?(Z|[+-]\d\d:?\d\d)?\]?"
        ), "iso"),
        (re.compile(r"^\[?(\d{4})/(\d\d)/(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:[.,](\d{1,9}))?\]?"), "iso"),
        (re.compile(r"^\[?(\d\d)\.(\d\d)\.(\d{4})[ ,]+(\d\d):(\d\d):(\d\d)(?:[.,](\d{1,9}))?\]?"), "german"),
        (re.compile(rf"^({_MONTH}) +(\d{{1,2}}) (\d\d):(\d\d):(\d\d)(?:\.(\d{{1,6}}))?"), "syslog"),
    )
    LEVEL = re.compile(r"(?i)\b(error|fatal|critical|warn(?:ing)?)\b")

    def recognizes(self, line: str) -> bool:
        return any(pattern.match(line) for pattern, _ in self.PATTERNS)

    def parse(self, lines: Iterable[str], hints: Hints) -> Iterator[Event]:
        def parse_line(line: str, number: int) -> Event | None:
            for pattern, shape in self.PATTERNS:
                match = pattern.match(line)
                if not match:
                    continue
                offset, flag = None, "local"
                if shape == "iso":
                    groups = match.groups()
                    wall = wall_time(*groups[:7])
                    if len(groups) > 7 and groups[7]:
                        offset, flag = offset_minutes(groups[7]), "exact"
                elif shape == "german":
                    d, m, y, hh, mi, ss, frac = match.groups()
                    wall = wall_time(y, m, d, hh, mi, ss, frac)
                else:
                    month, day, hh, mi, ss, frac = match.groups()
                    # Syslog leaves out the year; the file name or today supplies it.
                    year = hints.file_date.year if hints.file_date else date.today().year
                    wall = wall_time(year, MONTHS[month.lower()], day, hh, mi, ss, frac)
                    flag = "ambiguous" if hints.file_date is None else "local"
                level = self.LEVEL.search(line[match.end():match.end() + 60])
                severity = LEVELS.get(level.group(1).lower(), INFO) if level else INFO
                return Event(number, number, line, wall=wall, offset=offset, ts_flag=flag if wall else "invalid",
                             severity=severity)
            return None

        return self._line_events(lines, parse_line)


FORMATS: list[Callable[[], Format]] = [MDaemonEventLog, ComponentLog, BracketLog, AccessLog, PipeLog, CtimeLog]


def detect(sample: list[str]) -> Format:
    """The format that recognizes most sample lines; the generic one below a third."""
    lines = [line for line in sample if line.strip()][:200]
    best, best_score = None, 0.0
    for factory in FORMATS:
        candidate = factory()
        score = candidate.score(lines)
        if score > best_score:
            best, best_score = candidate, score
    return best if best is not None and best_score >= 0.34 else GenericLog()
