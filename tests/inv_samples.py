"""Synthetic logs in the layouts of MDaemon 26 and its web services.

Only documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
.example domains and invented accounts. The line shapes follow real logs; the
values tell a small story the tests follow:

* alpha logs in by IMAP, ActiveSync, WebDAV and the web interface from
  CLIENT_IP around 08:05; the same address shows up in the RTC log a few
  minutes later and in an ActiveSync request of gamma in the afternoon.
* gamma, delta and epsilon log in from NAT_IP, an address they share.
* beta, at partner.example, sends alpha a message: it is converted from
  RAW_FILE to MSG_FILE, scanned by the antivirus and the content filter, and
  carries MSGID_IN all the way.
* A message of the next day, MSGID_OUT, is signed, checked by spamd and seen
  by the PGP plug-in, each time in another queue file.
* beta also logs in by IMAP, at a time of its own.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

ALPHA = "alpha@firma.example"
BETA = "beta@partner.example"
GAMMA = "gamma@firma.example"
DELTA = "delta@firma.example"
EPSILON = "epsilon@firma.example"
CLIENT_IP = "198.51.100.20"
NAT_IP = "198.51.100.99"
BETA_IP = "203.0.113.50"
SERVER_IP = "192.0.2.10"
DEVICE = "SYNTHDEVICE0001"
MSGID_IN = "synth.0001@partner.example"
MSGID_OUT = "synth.0002@firma.example"
RAW_FILE = "md50000000001.raw"
MSG_FILE = "md50000000002.msg"
DKIM_FILE = "md50000000020.msg"
PGP_FILE = "md50000000030.msg"
REQUEST = "BCDEFGHJKL"


def _session(day: str, start: str, number: int, client: str, account: str, command: str = "SELECT INBOX") -> list[str]:
    stamp = f"{day} {start}"
    return [
        f"{stamp}.000: Session {number:08d}; child 0001",
        f"{stamp}.010: Accepting IMAP connection from {client}:{51000 + number} to {SERVER_IP}:993",
        f"{stamp}.020: SSL-Protokollverhandlung erfolgreich (TLS 1.3)",
        f"{stamp}.030: Authenticated as {account}",
        f"{stamp}.040: <-- c1 {command}",
        f"{stamp}.050: --> c1 OK completed",
        f"{stamp}.060: IMAP session complete, (2048 bytes)",
        f"{stamp}.070: ----------",
    ]


def imap_log() -> str:
    day = "Wed 2026-10-21"
    lines = ["START Event Log"]
    lines += _session(day, "08:05:00", 1, CLIENT_IP, ALPHA)
    lines += _session(day, "09:00:00", 2, NAT_IP, GAMMA)
    lines += _session(day, "09:01:00", 3, NAT_IP, DELTA)
    lines += _session(day, "09:02:00", 4, NAT_IP, EPSILON)
    lines += _session(day, "11:00:00", 5, BETA_IP, BETA, "SELECT Archiv")
    # A long session, written in partial transcripts: every later part starts
    # with the last line of the part before.
    lines += [
        f"{day} 12:00:00.000: --------- Partial transcript (session 00000006) ---------",
        f"{day} 12:00:00.000: Session 00000006; child 0002",
        f"{day} 12:00:00.010: Accepting IMAP connection from 203.0.113.60:50001 to {SERVER_IP}:993",
        f"{day} 12:00:00.030: Authenticated as {GAMMA}",
        f"{day} 12:00:01.000: <-- c1 SELECT INBOX",
        f"{day} 12:00:01.000: ---------- End partial transcript",
        f"{day} 12:05:00.000: --------- Partial transcript (session 00000006) ---------",
        f"{day} 12:00:01.000: <-- c1 SELECT INBOX",
        f"{day} 12:05:00.000: <-- c2 FETCH 1:* (FLAGS)",
        f"{day} 12:05:00.000: ---------- End partial transcript",
        f"{day} 12:05:00.000: <-- c2 FETCH 1:* (FLAGS)",
        f"{day} 12:10:00.010: <-- c3 Folder hierarchy listed",
        "    * LIST (\\HasNoChildren) \"/\" Archiv",
        f"{day} 12:10:00.020: IMAP session complete, (512 bytes)",
        f"{day} 12:10:00.030: ----------",
    ]
    # The service restarts: session numbers begin again.
    lines += ["START Event Log"]
    lines += _session(day, "13:00:00", 1, "203.0.113.80", EPSILON)
    return "\n".join(lines) + "\n"


def raw_log() -> str:
    day = "Wed 2026-10-21"
    return "\n".join([
        "Server Shutdown Wed, 21 Oct 2026 07:59:00 +0200",
        "START Event Log",
        f"{day} 10:00:00.000: <{RAW_FILE}> wird umgewandelt",
        f"{day} 10:00:00.010: * Message return-path: {BETA}",
        f"{day} 10:00:00.020: * Message from: {BETA}",
        f"{day} 10:00:00.030: * Message to: {ALPHA}",
        f"{day} 10:00:00.040: * Message-ID: <{MSGID_IN}>",
        f"{day} 10:00:00.050: * Größe: 4096 Bytes",
        f"{day} 10:00:00.060: Umwandlung abgeschlossen ({MSG_FILE} erstellt)",
        f"{day} 10:00:00.070: ----------",
    ]) + "\n"


def antivirus_log() -> str:
    day = "Wed 2026-10-21"
    return "\n".join([
        f"{day} 10:00:01.000: MDaemon AntiVirus processing c:\\mdaemon\\queues\\local\\{MSG_FILE}...",
        f"{day} 10:00:01.010: * Message from: {BETA}",
        f"{day} 10:00:01.020: * Message to: {ALPHA}",
        f"{day} 10:00:01.030: * Message-ID: <{MSGID_IN}>",
        f"{day} 10:00:01.040: * Total attachments scanned  : 1",
        f"{day} 10:00:01.050: * Total attachments infected  : 0",
        f"{day} 10:00:01.060: ----------",
    ]) + "\n"


def content_filter_log() -> str:
    day = "Wed 2026-10-21"
    return "\n".join([
        f"{day} 10:00:02.000: Content Filter processing {MSG_FILE}...",
        f"{day} 10:00:02.010: * Message from: {BETA}",
        f"{day} 10:00:02.020: * Message to: {ALPHA}",
        f"{day} 10:00:02.030: * Message-ID: <{MSGID_IN}>",
        f"{day} 10:00:02.040: * Matched 1 of 12 active rules",
        f"{day} 10:00:02.050: ----------",
    ]) + "\n"


def dkim_log() -> str:
    day = "Thu 2026-10-22"
    return "\n".join([
        f"{day} 09:00:00.000: Performing DKIM signing",
        f"{day} 09:00:00.010: * File: c:\\mdaemon\\queues\\remote\\{DKIM_FILE}",
        f"{day} 09:00:00.020: * Message-ID: <{MSGID_OUT}>",
        f"{day} 09:00:00.030: *  Result: OK",
        f"{day} 09:00:00.040: ----------",
    ]) + "\n"


def spamd_log() -> str:
    day = "Thu 2026-10-22"
    return "\n".join([
        f"{day} 09:00:01.000: Oct 22 09:00:01.100 [4242] info: spamd: connection from localhost [127.0.0.1]:56333 to port 783, fd 5",
        f"{day} 09:00:01.200: Oct 22 09:00:01.200 [4242] info: spamd: processing message <{MSGID_OUT}> for mdaemon:1000",
        f"{day} 09:00:01.300: Oct 22 09:00:01.300 [4242] info: spamd: clean message (0.4/5.0) for mdaemon:1000 in 0.2 seconds",
    ]) + "\n"


def pgp_log() -> str:
    day = "Thu 2026-10-22"
    return "\n".join([
        f"{day} 09:00:02.000: Verarbeite {PGP_FILE}",
        f"{day} 09:00:02.010: * Message-ID: <{MSGID_OUT}>",
        f"{day} 09:00:02.020: * Nachricht nicht verschlüsselt",
        f"{day} 09:00:02.030: ----------",
    ]) + "\n"


def activesync_log() -> str:
    return "\n".join([
        f"261021 080510123 I [0002B7C1] 0x41330080 Connection: IP:{CLIENT_IP} SRV:mail.firma.example RM:POST "
        f"QS:Cmd=Sync&User={ALPHA}&DeviceId={DEVICE}&DeviceType=SmartPhone",
        f"261021 080510200 I [0002B7C1] Authenticated: {ALPHA}",
        "261021 080510300 I [0002B7C1] Sending HTTP/200",
        "261021 080510400 D [0002B7C1] Sync session terminating",
        f"261021 140000000 I [0002B7C2] 0x41330080 Connection: IP:{CLIENT_IP} SRV:mail.firma.example RM:POST "
        f"QS:Cmd=Ping&User={GAMMA}&DeviceId=SYNTHDEVICE0002",
    ]) + "\n"


def webdav_log() -> str:
    return "\n".join([
        f"[Wed 2026-10-21 08:06:00] INFO, [CQBWHWRBDV] Connection: {CLIENT_IP} Method:PROPFIND",
        "[Wed 2026-10-21 08:06:00] INFO, [CQBWHWRBDV] Send HTTP Error: 401 - No 'Authorization' header",
        f"[Wed 2026-10-21 08:06:01] INFO, [{REQUEST}] Connection: {CLIENT_IP} Method:PROPFIND",
        f"[Wed 2026-10-21 08:06:01] INFO, [{REQUEST}] Authenticate: {ALPHA} successfully authenticated",
        "[Wed 2026-10-21 08:06:30] WARNING, [MNPQRSTUVW] Send HTTP Error: 404 - Not Found",
    ]) + "\n"


def http_log() -> str:
    return "\n".join([
        f'{CLIENT_IP} - {ALPHA} [21/Oct/2026:08:07:00 +0200] "GET /WorldClient.dll?View=Main HTTP/1.1" 200 4096',
        '203.0.113.70 - - [21/Oct/2026:08:07:30 +0200] "GET /WorldClient.dll?View=Logon HTTP/1.1" 401 512',
    ]) + "\n"


def pipe_log() -> str:
    return "\n".join([
        f"2026-10-21 08:08:00 | WARNING | 404 Not Found: GET /rtc/session from ::ffff:{CLIENT_IP}",
        "2026-10-21 08:08:30 | INFO | Client registered",
    ]) + "\n"


def clamd_log() -> str:
    return "\n".join([
        "Wed Oct 21 08:05:30 2026 -> SelfCheck: Database status OK.",
        "Wed Oct 21 08:09:30 2026 -> WARNING: Signature database is older than 7 days",
    ]) + "\n"


def generic_log() -> str:
    return "\n".join([
        "2026-10-21T08:10:00+02:00 relay accepted from 198.51.100.120 for gamma@firma.example",
        "2026-10-21T08:10:05+02:00 relay ERROR delivery to delta@firma.example failed",
        "  retry scheduled in 15 minutes",
    ]) + "\n"


SAMPLES = {
    "MDaemon-2026-10-21-IMAP.log": (imap_log, "utf-8"),
    "MDaemon-2026-10-21-RAW.log": (raw_log, "cp1252"),
    "MDaemon-2026-10-21-AntiVirus.log": (antivirus_log, "cp1252"),
    "MDaemon-2026-10-21-Inhaltsfilter.log": (content_filter_log, "utf-8-sig"),
    "MDaemon-2026-10-22-DKIM.log": (dkim_log, "utf-8"),
    "MDaemon-2026-10-22-MDSpamD.log": (spamd_log, "utf-8"),
    "MDaemon-2026-10-22-MDPGP.log": (pgp_log, "utf-8"),
    "AirSync-2026-10-21.log": (activesync_log, "utf-8"),
    "WebDAV-2026-10-21.log": (webdav_log, "utf-8"),
    "HTTP-2026-10-21.log": (http_log, "utf-8"),
    "RTCServer-2026-10-21.log": (pipe_log, "utf-8"),
    "ClamD-2026-10-21.log": (clamd_log, "utf-8"),
    "Relay-2026-10-21.log": (generic_log, "utf-8"),
}


def write_samples(folder: Path) -> dict[str, Path]:
    folder.mkdir(parents=True, exist_ok=True)
    paths = {}
    for name, (build, encoding) in SAMPLES.items():
        path = folder / name
        path.write_bytes(build().encode(encoding))
        paths[name] = path
    return paths


def large_log(path: Path, sessions: int = 4000, day: str = "2026-10-21") -> Path:
    """An IMAP log with many sessions, about seven lines each."""
    weekday = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")[date.fromisoformat(day).weekday()]
    lines = ["START Event Log"]
    for number in range(1, sessions + 1):
        second = number % 60
        minute = (number // 60) % 60
        hour = 8 + number // 3600
        stamp = f"{weekday} {day} {hour:02d}:{minute:02d}:{second:02d}"
        account = f"konto{number % 200:03d}@firma.example"
        address = f"198.51.100.{number % 250 + 1}"
        lines += [
            f"{stamp}.000: Session {number:08d}; child 0001",
            f"{stamp}.010: Accepting IMAP connection from {address}:{40000 + number % 20000} to {SERVER_IP}:993",
            f"{stamp}.020: SSL-Protokollverhandlung erfolgreich (TLS 1.3)",
            f"{stamp}.030: Authenticated as {account}",
            f"{stamp}.040: <-- c{number} SELECT INBOX",
            f"{stamp}.050: IMAP session complete, (100 bytes)",
            f"{stamp}.060: ----------",
        ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
