"""Log Investigator: import, entities, time, correlation, search and export.

All logs are synthetic (see inv_samples.py): documentation addresses, .example
domains, invented accounts. They follow the structures of real MDaemon logs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import inv_samples as S  # noqa: E402

from logmasque import entities, investigate, logformats  # noqa: E402
from logmasque.anonymize import Anonymizer, Options  # noqa: E402
from logmasque.investigate import DIRECT, POSSIBLE, STRONG  # noqa: E402
from logmasque.mapping import Mapping  # noqa: E402

TEXT = investigate.TEXT_SQL  # the text of the event e


def _fingerprint(path: Path) -> tuple[int, str]:
    return path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()


class SampleInvestigation(unittest.TestCase):
    """One investigation over all sample logs, shared by the read-only tests."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.logs = S.write_samples(cls.root / "logs")
        cls.before = {name: _fingerprint(path) for name, path in cls.logs.items()}
        cls.inv = investigate.create_investigation(cls.root / "inv", "Beispiel")
        cls.report = cls.inv.import_paths([str(cls.root / "logs")])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def entity(self, kind, value):
        with self.inv.connect() as db:
            row = db.execute("SELECT id FROM entities WHERE kind = ? AND value = ?", (kind, value)).fetchone()
        self.assertIsNotNone(row, f"{kind} {value} not found")
        return row[0]

    def event(self, name, line):
        with self.inv.connect() as db:
            row = db.execute(
                "SELECT e.id FROM events e JOIN sources s ON s.id = e.source_id WHERE s.name = ? AND e.line_start = ?",
                (name, line),
            ).fetchone()
        self.assertIsNotNone(row, f"{name}:{line} not found")
        return row[0]

    def trace(self, *anchors, temporal=0):
        """(file, line) -> (level, basis) of every event in the trace."""
        with self.inv.connect() as db:
            result = self.inv._trace(db, tuple(sorted(anchors)), temporal)
            rows = {}
            for event_id, (level, basis, _) in result["events"].items():
                name, line = db.execute(
                    "SELECT s.name, e.line_start FROM events e JOIN sources s ON s.id = e.source_id WHERE e.id = ?",
                    (event_id,),
                ).fetchone()
                rows[(name, line)] = (level, basis)
        return rows


IMAP = "MDaemon-2026-10-21-IMAP.log"


class ImportTest(SampleInvestigation):
    def test_every_format_and_encoding_is_recognized(self):
        self.assertEqual(self.report["failed"], [])
        sources = {item["name"]: item for item in self.inv.overview()["sources"]}
        self.assertEqual(set(sources), set(S.SAMPLES))
        expected = {
            IMAP: "mdaemon", "AirSync-2026-10-21.log": "mdaemon-component", "WebDAV-2026-10-21.log": "bracket",
            "HTTP-2026-10-21.log": "access", "RTCServer-2026-10-21.log": "pipe", "ClamD-2026-10-21.log": "ctime",
            "Relay-2026-10-21.log": "generic",
        }
        for name, parser in expected.items():
            self.assertEqual(sources[name]["parser"], parser, name)
        self.assertEqual(sources["MDaemon-2026-10-21-RAW.log"]["encoding"], "cp1252")
        self.assertEqual(sources["MDaemon-2026-10-21-Inhaltsfilter.log"]["encoding"], "utf-8-sig")
        self.assertEqual(sources[IMAP]["encoding"], "utf-8")
        self.assertTrue(all(source["state"] == "ready" for source in sources.values()))

    def test_the_originals_stay_unchanged(self):
        self.assertEqual({name: _fingerprint(path) for name, path in self.logs.items()}, self.before)

    def test_stored_events_are_exactly_the_original_lines(self):
        with self.inv.connect() as db:
            rows = db.execute(
                f"SELECT {TEXT}, e.line_start, e.line_end, s.path, s.encoding FROM events e "
                "JOIN sources s ON s.id = e.source_id"
            ).fetchall()
        files = {}
        for message, start, end, path, encoding in rows:
            if path not in files:
                with open(path, "r", encoding=encoding, newline="") as handle:
                    files[path] = [line.rstrip("\r\n") for line in handle]
            original = [line for line in files[path][start - 1:end] if line.strip()]
            self.assertEqual(message.split("\n"), original, f"{Path(path).name}:{start}")

    def test_byte_identical_files_are_imported_once(self):
        copy = self.root / "kopie"
        copy.mkdir(exist_ok=True)
        shutil.copy(self.logs["HTTP-2026-10-21.log"], copy / "HTTP-Kopie.log")
        report = self.inv.import_paths([str(self.root / "logs"), str(copy)])
        self.assertEqual(report["imported"], [])
        self.assertEqual(len(report["duplicates"]), len(S.SAMPLES) + 1)

    def test_a_missing_path_is_reported(self):
        with self.assertRaises(investigate.InvestigationError):
            self.inv.import_paths([str(self.root / "gibt-es-nicht")])

    def test_event_types_and_severities(self):
        with self.inv.connect() as db:
            rows = {(name, line): (etype, severity) for name, line, etype, severity in db.execute(
                "SELECT s.name, e.line_start, e.etype, e.severity FROM events e JOIN sources s ON s.id = e.source_id"
            )}
        I, W, E = logformats.INFO, logformats.WARNING, logformats.ERROR
        self.assertEqual(rows[(IMAP, 5)], ("auth.ok", I))
        self.assertEqual(rows[(IMAP, 3)], ("conn.accept", I))
        self.assertEqual(rows[(IMAP, 6)], ("proto", logformats.DETAIL))
        self.assertEqual(rows[("MDaemon-2026-10-21-RAW.log", 3)], ("raw.convert", I))
        self.assertEqual(rows[("MDaemon-2026-10-21-AntiVirus.log", 1)], ("av.scan", I))
        self.assertEqual(rows[("MDaemon-2026-10-21-Inhaltsfilter.log", 1)], ("filter.scan", W))
        self.assertEqual(rows[("MDaemon-2026-10-22-DKIM.log", 1)], ("dkim.sign", I))
        self.assertEqual(rows[("MDaemon-2026-10-22-MDSpamD.log", 2)], ("spamd.process", I))
        self.assertEqual(rows[("MDaemon-2026-10-22-MDPGP.log", 1)], ("pgp.process", I))
        self.assertEqual(rows[("AirSync-2026-10-21.log", 1)], ("activesync.request", I))
        self.assertEqual(rows[("WebDAV-2026-10-21.log", 2)], ("http.challenge", I))
        self.assertEqual(rows[("WebDAV-2026-10-21.log", 4)], ("auth.ok", I))
        self.assertEqual(rows[("HTTP-2026-10-21.log", 2)], ("http.request", W))
        self.assertEqual(rows[("RTCServer-2026-10-21.log", 1)], ("http.request", W))
        self.assertEqual(rows[("ClamD-2026-10-21.log", 2)], ("line", W))
        self.assertEqual(rows[("Relay-2026-10-21.log", 2)], ("line", E))

    def test_identifiers_carry_their_roles(self):
        with self.inv.connect() as db:
            roles = {(kind, value, role) for kind, value, role in db.execute(
                "SELECT n.kind, n.value, o.role FROM occurrences o JOIN entities n ON n.id = o.entity_id "
                "JOIN events e ON e.id = o.event_id JOIN sources s ON s.id = e.source_id WHERE s.name IN (?, ?)",
                ("MDaemon-2026-10-21-RAW.log", "MDaemon-2026-10-21-AntiVirus.log"),
            )}
        # A value keeps the first role it has in an event: return-path in RAW, from in the virus scan.
        self.assertIn(("email", S.BETA, "return-path"), roles)
        self.assertIn(("email", S.BETA, "from"), roles)
        self.assertIn(("email", S.ALPHA, "to"), roles)
        self.assertIn(("msgid", S.MSGID_IN, ""), roles)
        self.assertIn(("queue", S.RAW_FILE, ""), roles)
        self.assertIn(("queue", S.MSG_FILE, ""), roles)
        with self.inv.connect() as db:
            server = {row[0] for row in db.execute(
                "SELECT DISTINCT o.role FROM occurrences o JOIN entities n ON n.id = o.entity_id "
                "WHERE n.kind = 'ipv4' AND n.value = ?", (S.SERVER_IP,)
            )}
            device = db.execute("SELECT COUNT(*) FROM entities WHERE kind = 'device' AND value = ?", (S.DEVICE,)).fetchone()[0]
        self.assertEqual(server, {"server"})
        self.assertEqual(device, 1)


class SessionTest(SampleInvestigation):
    def contexts(self, name):
        with self.inv.connect() as db:
            return {line: key for line, key in db.execute(
                "SELECT e.line_start, c.key FROM events e JOIN sources s ON s.id = e.source_id "
                "LEFT JOIN contexts c ON c.id = e.ctx WHERE s.name = ?", (name,)
            )}

    def test_the_lines_of_a_session_share_it(self):
        contexts = self.contexts(IMAP)
        self.assertEqual(len({contexts[line] for line in range(2, 10)}), 1)
        self.assertNotEqual(contexts[2], contexts[10])

    def test_partial_transcripts_form_one_session(self):
        contexts = self.contexts(IMAP)
        session = contexts[43]
        self.assertTrue(session.endswith(":session:1:00000006"))
        for line in (44, 45, 46, 50, 53, 55, 56):
            self.assertEqual(contexts[line], session, line)
        # A part repeats the last line of the part before; it is not counted twice.
        self.assertNotIn(49, contexts)
        self.assertNotIn(52, contexts)
        # An indented line without a time belongs to the line before.
        with self.inv.connect() as db:
            end = db.execute(
                "SELECT e.line_end FROM events e JOIN sources s ON s.id = e.source_id WHERE s.name = ? AND e.line_start = 53",
                (IMAP,),
            ).fetchone()[0]
        self.assertEqual(end, 54)

    def test_session_numbers_begin_again_after_a_restart(self):
        contexts = self.contexts(IMAP)
        self.assertTrue(contexts[2].endswith(":session:1:00000001"))
        self.assertTrue(contexts[58].endswith(":session:2:00000001"))
        trace = self.trace(self.entity("email", S.ALPHA))
        self.assertNotIn((IMAP, 58), trace)

    def test_requests_group_their_lines(self):
        event_id = self.event("WebDAV-2026-10-21.log", 4)
        detail = self.inv.event_detail(event_id)
        self.assertTrue(detail["contextLabel"].startswith(f"Request {S.REQUEST}"))
        self.assertEqual(detail["contextSize"], 2)
        self.assertEqual([row["line"] for row in self.inv.context_events(event_id)], [3, 4])

    def test_a_processing_block_is_one_event(self):
        with self.inv.connect() as db:
            start, end, text = db.execute(
                f"SELECT e.line_start, e.line_end, {TEXT} FROM events e JOIN sources s ON s.id = e.source_id "
                "WHERE s.name = 'MDaemon-2026-10-21-AntiVirus.log'"
            ).fetchone()
        self.assertEqual((start, end), (1, 7))
        self.assertEqual(len(text.split("\n")), 7)

    def test_a_long_lived_request_id_is_a_worker_and_no_context(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "AirSync-2026-10-23.log"
            path.write_text(
                "261023 080000000 I [0000AAAA] Worker started\n"
                "261023 100000000 I [0000AAAA] Worker still running\n"
                "261023 100000100 I [0000BBBB] Authenticated: alpha@firma.example\n",
                encoding="utf-8",
            )
            inv = investigate.create_investigation(Path(folder) / "inv", "Worker")
            inv.import_paths([str(path)])
            with inv.connect() as db:
                rows = dict(db.execute("SELECT line_start, ctx FROM events"))
                requests = {row[0] for row in db.execute("SELECT value FROM entities WHERE kind = 'request'")}
        self.assertIsNone(rows[1])
        self.assertIsNone(rows[2])
        self.assertIsNotNone(rows[3])
        self.assertEqual(len(requests), 1)


class TimeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.logs = S.write_samples(self.root / "logs")
        self.inv = investigate.create_investigation(self.root / "inv", "Zeit")

    def tearDown(self):
        self.tmp.cleanup()

    def first(self, sql, *params):
        with self.inv.connect() as db:
            return db.execute(sql, params).fetchone()

    def wall_and_time(self, name, line):
        return self.first(
            "SELECT e.wall_ms, e.ts_ms, e.ts_flag, e.off_min FROM events e JOIN sources s ON s.id = e.source_id "
            "WHERE s.name = ? AND e.line_start = ?", name, line,
        )

    def test_stated_zones_and_the_zone_the_others_agree_on(self):
        self.inv.import_paths([str(self.logs[name]) for name in ("HTTP-2026-10-21.log", IMAP, "AirSync-2026-10-21.log")])
        wall, ts, flag, offset = self.wall_and_time("HTTP-2026-10-21.log", 1)
        self.assertEqual((flag, offset), ("exact", 120))
        self.assertEqual(ts, wall - 120 * 60000)
        wall, ts, flag, offset = self.wall_and_time(IMAP, 5)
        self.assertEqual((flag, offset), ("inferred", 120))
        self.assertEqual(ts, wall - 120 * 60000)
        overview = self.inv.overview()
        self.assertEqual((overview["naiveOffset"], overview["naiveFlag"]), (120, "inferred"))

    def test_without_a_stated_zone_this_computers_zone_is_taken(self):
        self.inv.import_paths([str(self.logs[IMAP])])
        wall, ts, flag, offset = self.wall_and_time(IMAP, 5)
        self.assertEqual(flag, "local")
        self.assertEqual(ts, wall - investigate.local_offset(wall) * 60000)

    def test_a_zone_the_file_states(self):
        self.inv.import_paths([str(self.logs["MDaemon-2026-10-21-RAW.log"])])
        wall, ts, flag, offset = self.wall_and_time("MDaemon-2026-10-21-RAW.log", 3)
        self.assertEqual((flag, offset), ("source", 120))
        self.assertEqual(ts, wall - 120 * 60000)

    def test_disagreeing_zones_leave_this_computers_zone(self):
        other = self.root / "Relay-2026-10-22.log"
        other.write_text("2026-10-22T08:00:00+01:00 relay accepted from 198.51.100.121\n", encoding="utf-8")
        self.inv.import_paths([str(self.logs["Relay-2026-10-21.log"]), str(other), str(self.logs[IMAP])])
        self.assertEqual(self.wall_and_time(IMAP, 5)[2], "local")
        self.assertEqual(self.inv.overview()["naiveFlag"], "local")

    def test_a_later_file_that_states_a_zone_retimes_the_earlier_ones(self):
        self.inv.import_paths([str(self.logs[IMAP])])
        self.assertEqual(self.wall_and_time(IMAP, 5)[2], "local")
        self.inv.import_paths([str(self.logs["HTTP-2026-10-21.log"])])
        wall, ts, flag, offset = self.wall_and_time(IMAP, 5)
        self.assertEqual((flag, offset), ("inferred", 120))
        self.assertEqual(ts, wall - 120 * 60000)

    def test_fixed_default_zone_and_per_file_zone_and_clock(self):
        self.inv.import_paths([str(self.logs[IMAP]), str(self.logs["AirSync-2026-10-21.log"])])
        self.inv.set_time(None, "fixed", 60)
        wall, ts, flag, offset = self.wall_and_time(IMAP, 5)
        self.assertEqual((flag, offset), ("source", 60))
        self.assertEqual(ts, wall - 60 * 60000)
        source = next(item["id"] for item in self.inv.overview()["sources"] if item["name"] == IMAP)
        self.inv.set_time(source, "fixed", 0, 2)
        wall, ts, flag, offset = self.wall_and_time(IMAP, 5)
        self.assertEqual((offset, ts), (0, wall + 2000))
        # The other file keeps the default.
        wall, ts, _, offset = self.wall_and_time("AirSync-2026-10-21.log", 2)
        self.assertEqual((offset, ts), (60, wall - 60 * 60000))
        with self.assertRaises(investigate.InvestigationError):
            self.inv.set_time(None, "irgendwann")

    def test_broken_missing_and_borrowed_times(self):
        notes = self.root / "notes.log"
        notes.write_text(
            "a line without any time at all\n"
            "2026-10-21 08:00:00 service started\n"
            "a line that takes the time of the one before\n"
            "Oct 21 08:00:01 host syslog line without a year\n",
            encoding="utf-8",
        )
        broken = self.root / "MDaemon-2026-10-21-Broken.log"
        broken.write_text(
            "Wed 2026-10-21 08:00:00.000: fine\nWed 2026-13-21 08:00:01.000: thirteenth month\n", encoding="utf-8"
        )
        self.inv.import_paths([str(notes), str(broken)])
        with self.inv.connect() as db:
            flags = {(name, line): flag for name, line, flag in db.execute(
                "SELECT s.name, e.line_start, e.ts_flag FROM events e JOIN sources s ON s.id = e.source_id"
            )}
        self.assertEqual(flags[("notes.log", 1)], "none")
        self.assertEqual(flags[("notes.log", 2)], "local")
        self.assertEqual(flags[("notes.log", 3)], "inherited")
        self.assertEqual(flags[("notes.log", 4)], "ambiguous")
        self.assertEqual(flags[("MDaemon-2026-10-21-Broken.log", 2)], "invalid")
        self.assertIsNone(self.wall_and_time("MDaemon-2026-10-21-Broken.log", 2)[1])

    def test_events_come_in_time_order_and_those_without_time_last(self):
        self.inv.import_paths([str(self.root / "logs")])
        rows = self.inv.search("", min_severity=0, limit=1000)["rows"]
        stamps = [row["ts"] for row in rows]
        timed = [stamp for stamp in stamps if stamp is not None]
        self.assertEqual(timed, sorted(timed))
        self.assertTrue(all(stamp is None for stamp in stamps[len(timed):]))
        self.assertIn(None, stamps)


class CorrelationTest(SampleInvestigation):
    def test_a_persons_trace_with_its_levels(self):
        trace = self.trace(self.entity("email", S.ALPHA))
        direct = {key for key, (level, _) in trace.items() if level == DIRECT}
        for line in range(2, 10):
            self.assertIn((IMAP, line), direct)
        for key in [("AirSync-2026-10-21.log", line) for line in (1, 2, 3, 4)] + [
            ("WebDAV-2026-10-21.log", 3), ("WebDAV-2026-10-21.log", 4), ("HTTP-2026-10-21.log", 1),
            ("MDaemon-2026-10-21-RAW.log", 3), ("MDaemon-2026-10-21-AntiVirus.log", 1),
            ("MDaemon-2026-10-21-Inhaltsfilter.log", 1),
        ]:
            self.assertIn(key, direct)
        # The same address a few minutes later: strong; hours later: possible.
        self.assertEqual(trace[("RTCServer-2026-10-21.log", 1)][0], STRONG)
        self.assertIn(S.CLIENT_IP, trace[("RTCServer-2026-10-21.log", 1)][1])
        self.assertIn("zeitlich nah", trace[("RTCServer-2026-10-21.log", 1)][1])
        self.assertEqual(trace[("WebDAV-2026-10-21.log", 1)][0], STRONG)
        self.assertEqual(trace[("AirSync-2026-10-21.log", 5)][0], POSSIBLE)
        self.assertIn("zeitlich entfernt", trace[("AirSync-2026-10-21.log", 5)][1])

    def test_every_link_names_its_basis(self):
        trace = self.trace(self.entity("email", S.ALPHA))
        self.assertTrue(all(basis for _, basis in trace.values()))
        self.assertEqual(trace[(IMAP, 5)][1], f"enthält E-Mail-Adresse {S.ALPHA}")
        self.assertEqual(trace[(IMAP, 6)][1], "gleiche Sitzung, Request oder Verarbeitung")

    def test_correspondents_do_not_widen_a_persons_trace(self):
        # beta wrote to alpha; beta's own login is somebody else's business.
        trace = self.trace(self.entity("email", S.ALPHA))
        self.assertFalse(any(key[0] == IMAP and 34 <= key[1] <= 41 for key in trace))
        trace = self.trace(self.entity("email", S.BETA))
        self.assertFalse(any(key[0] == IMAP and 2 <= key[1] <= 9 for key in trace))

    def test_the_queue_file_chain_of_an_incoming_message(self):
        trace = self.trace(self.entity("queue", S.RAW_FILE))
        self.assertEqual(trace[("MDaemon-2026-10-21-RAW.log", 3)][0], DIRECT)
        self.assertEqual(trace[("MDaemon-2026-10-21-AntiVirus.log", 1)][0], DIRECT)
        self.assertEqual(trace[("MDaemon-2026-10-21-Inhaltsfilter.log", 1)][0], DIRECT)
        self.assertTrue(trace[("MDaemon-2026-10-21-AntiVirus.log", 1)][1].startswith("gleiche "))

    def test_the_message_id_links_dkim_spamd_and_pgp(self):
        trace = self.trace(self.entity("msgid", S.MSGID_OUT))
        self.assertEqual(
            {key for key, (level, _) in trace.items() if level == DIRECT},
            {("MDaemon-2026-10-22-DKIM.log", 1), ("MDaemon-2026-10-22-MDSpamD.log", 2), ("MDaemon-2026-10-22-MDPGP.log", 1)},
        )

    def test_for_a_message_its_parties_are_followed(self):
        trace = self.trace(self.entity("msgid", S.MSGID_IN))
        self.assertEqual(trace[(IMAP, 37)][0], POSSIBLE)
        self.assertIn(S.BETA, trace[(IMAP, 37)][1])
        self.assertEqual(trace[(IMAP, 5)][0], POSSIBLE)

    def test_the_server_address_links_nothing(self):
        server = self.entity("ipv4", S.SERVER_IP)
        self.assertTrue(self.inv.entity_detail(server)["common"])
        trace = self.trace(self.entity("email", S.EPSILON))
        self.assertFalse(any(key[0] == IMAP and 34 <= key[1] <= 41 for key in trace))

    def test_a_shared_address_only_hints_close_in_time(self):
        nat = self.entity("ipv4", S.NAT_IP)
        self.assertTrue(self.inv.entity_detail(nat)["common"])
        trace = self.trace(self.entity("email", S.GAMMA))
        for line in (19, 27):  # the logins of delta and epsilon from the same address
            level, basis = trace[(IMAP, line)]
            self.assertEqual(level, POSSIBLE)
            self.assertTrue(basis.startswith("geteilte Adresse"))
        self.assertNotIn((IMAP, 21), trace)  # delta's login itself is in the session, not linked

    def test_closeness_in_time_only_when_asked_for(self):
        alpha = self.entity("email", S.ALPHA)
        self.assertNotIn(("ClamD-2026-10-21.log", 1), self.trace(alpha))
        level, basis = self.trace(alpha, temporal=60)[("ClamD-2026-10-21.log", 1)]
        self.assertEqual(level, POSSIBLE)
        self.assertTrue(basis.startswith("nur zeitliche Nähe"))

    def test_a_message_id_seen_in_many_contexts_stops_linking(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "MDaemon-2026-10-21-AntiVirus.log"
            lines = []
            for number in range(investigate.COMMON_MIN_GROUPS + 5):
                stamp = f"Wed 2026-10-21 08:{number // 60:02d}:{number % 60:02d}"
                lines += [
                    f"{stamp}.000: MDaemon AntiVirus processing md5{number:010d}.msg...",
                    f"{stamp}.010: * Message-ID: <always.the.same@firma.example>",
                    f"{stamp}.020: ----------",
                ]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            inv = investigate.create_investigation(Path(folder) / "inv", "Häufig")
            inv.import_paths([str(path)])
            msgid = inv.find_entities("always.the.same@firma.example")[0]
            self.assertTrue(msgid["common"])
            queue = inv.find_entities("md50000000000.msg")[0]["id"]
            with inv.connect() as db:
                trace = inv._trace(db, (queue,), 0)
            self.assertEqual(len(trace["events"]), 1)


class ReviewTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        S.write_samples(self.root / "logs")
        self.inv = investigate.create_investigation(self.root / "inv", "Prüfung")
        self.inv.import_paths([str(self.root / "logs")])

    def tearDown(self):
        self.tmp.cleanup()

    def id(self, value):  # noqa: A003 - the entity of a value
        return self.inv.find_entities(value)[0]["id"]

    def levels(self, anchor):
        with self.inv.connect() as db:
            trace = self.inv._trace(db, (anchor,), 0)
            return {
                db.execute(f"SELECT {TEXT} FROM events e WHERE e.id = ?", (event_id,)).fetchone()[0]: item[0]
                for event_id, item in trace["events"].items()
            }

    def rtc(self, levels):
        return next((level for text, level in levels.items() if "/rtc/session" in text), None)

    def test_an_excluded_value_links_nothing_but_stays_searchable(self):
        alpha, client = self.id(S.ALPHA), self.id(S.CLIENT_IP)
        self.assertEqual(self.rtc(self.levels(alpha)), STRONG)
        self.assertTrue(self.inv.flag_entity(client, "exclude")["excluded"])
        self.assertIsNone(self.rtc(self.levels(alpha)))
        self.assertEqual(self.inv.search(S.CLIENT_IP)["mode"], "trace")
        self.assertFalse(self.inv.flag_entity(client, "reset")["excluded"])
        self.assertEqual(self.rtc(self.levels(alpha)), STRONG)

    def test_a_frequent_value_can_be_used_on_purpose(self):
        gamma, nat = self.id(S.GAMMA), self.id(S.NAT_IP)
        delta_login = next(text for text in self.levels(gamma) if f"from {S.NAT_IP}:51003" in text)
        self.assertEqual(self.levels(gamma)[delta_login], POSSIBLE)
        self.assertTrue(self.inv.flag_entity(nat, "include")["included"])
        self.assertEqual(self.levels(gamma)[delta_login], STRONG)

    def test_a_single_link_can_be_excluded_and_restored(self):
        alpha, client = self.id(S.ALPHA), self.id(S.CLIENT_IP)
        self.inv.exclude_link(alpha, client)
        self.assertIsNone(self.rtc(self.levels(alpha)))
        related = {item["id"] for item in self.inv.entity_detail(alpha)["related"]}
        self.assertNotIn(client, related)
        graph = self.inv.graph(alpha)
        self.assertFalse(any({edge["a"], edge["b"]} == {alpha, client} for edge in graph["edges"]))
        self.inv.exclude_link(client, alpha, undo=True)
        self.assertEqual(self.rtc(self.levels(alpha)), STRONG)

    def test_decisions_are_kept_in_the_investigation(self):
        client = self.id(S.CLIENT_IP)
        self.inv.flag_entity(client, "exclude")
        again = investigate.Investigation(self.inv.path)
        self.assertTrue(again.entity_detail(client)["excluded"])
        with self.assertRaises(investigate.InvestigationError):
            again.flag_entity(client, "vielleicht")


class SearchTest(SampleInvestigation):
    def test_a_known_value_becomes_its_trace(self):
        result = self.inv.search(S.ALPHA)
        self.assertEqual(result["mode"], "trace")
        self.assertEqual([item["value"] for item in result["anchors"]], [S.ALPHA])
        self.assertGreater(result["levels"]["direkt"], 10)
        self.assertTrue(all("level" in row and row["basis"] for row in result["rows"]))

    def test_free_text_needs_every_word(self):
        result = self.inv.search("SELECT Archiv", min_severity=0)
        self.assertEqual(result["mode"], "text")
        self.assertEqual([(row["source"], row["line"]) for row in result["rows"]], [(IMAP, 38)])

    def test_a_trailing_star_searches_by_prefix(self):
        result = self.inv.search("Authenticat*", min_severity=0)
        self.assertGreaterEqual(result["total"], 8)
        self.assertTrue(all("Authenticat" in row["text"] for row in result["rows"]))

    def test_words_with_punctuation_match_as_written(self):
        self.assertEqual(self.inv.search("View=Main", min_severity=0)["total"], 1)
        self.assertEqual(self.inv.search("WorldClient.dll", min_severity=0)["total"], 2)
        self.assertEqual(self.inv.search("1:* (FLAGS)", min_severity=0)["total"], 1)

    def test_filters_combine(self):
        sources = {item["name"]: item["id"] for item in self.inv.overview()["sources"]}
        result = self.inv.search("", sources=[sources[IMAP]], etypes=["auth.ok"], min_severity=0)
        self.assertEqual([row["line"] for row in result["rows"]], [5, 13, 21, 29, 37, 45, 61])
        warnings = self.inv.search("", min_severity=logformats.WARNING)
        self.assertTrue(all(row["severity"] >= logformats.WARNING for row in warnings["rows"]))
        self.assertGreaterEqual(warnings["total"], 5)
        everything = self.inv.search("", min_severity=0, limit=1000)["rows"]
        timed = sorted(row["ts"] for row in everything if row["ts"] is not None)
        middle = timed[len(timed) // 2]
        later = self.inv.search("", min_severity=0, time_from=middle, limit=1000)["rows"]
        self.assertTrue(later and all(row["ts"] is not None and row["ts"] >= middle for row in later))
        earlier = self.inv.search("", min_severity=0, time_to=middle, limit=1000)["rows"]
        self.assertTrue(earlier and all(row["ts"] <= middle for row in earlier))

    def test_detail_lines_are_left_out_unless_asked_for(self):
        default = self.inv.search("SELECT INBOX")
        detail = self.inv.search("SELECT INBOX", min_severity=0)
        self.assertEqual(default["total"], 0)
        self.assertGreater(detail["total"], 0)

    def test_text_next_to_a_value_narrows_its_trace(self):
        result = self.inv.search("SELECT", entity_ids=[self.entity("email", S.ALPHA)], min_severity=0)
        self.assertEqual(result["mode"], "trace")
        self.assertEqual([(row["source"], row["line"]) for row in result["rows"]], [(IMAP, 6)])

    def test_levels_filter_a_trace(self):
        alpha = self.entity("email", S.ALPHA)
        strong = self.inv.search("", entity_ids=[alpha], levels=[STRONG], min_severity=0)
        self.assertEqual({row["level"] for row in strong["rows"]}, {STRONG})
        self.assertEqual(strong["total"], 2)

    def test_suggestions_show_kind_and_frequency(self):
        found = self.inv.suggest("alpha")
        self.assertEqual(found[0]["value"], S.ALPHA)
        self.assertEqual(found[0]["kindLabel"], "E-Mail-Adresse")
        queues = {item["value"] for item in self.inv.suggest("md500000000")}
        self.assertTrue({S.RAW_FILE, S.MSG_FILE} <= queues)
        self.assertEqual(self.inv.suggest("x"), [])
        self.assertTrue(self.inv.suggest(S.DEVICE))

    def test_values_are_found_however_they_are_written(self):
        self.assertEqual(self.inv.find_entities("ALPHA@FIRMA.EXAMPLE")[0]["value"], S.ALPHA)
        self.assertEqual(self.inv.find_entities(f"<{S.MSGID_IN}>")[0]["kind"], "msgid")
        self.assertEqual(self.inv.find_entities(f"::ffff:{S.CLIENT_IP}")[0]["value"], S.CLIENT_IP)
        self.assertEqual(self.inv.find_entities(f"c:\\mdaemon\\queues\\{S.MSG_FILE.upper()}")[0]["value"], S.MSG_FILE)

    def test_paging_and_ids(self):
        first = self.inv.search("", min_severity=0, limit=10)
        second = self.inv.search("", min_severity=0, limit=10, offset=10)
        self.assertEqual(len(first["rows"]), 10)
        self.assertFalse({row["id"] for row in first["rows"]} & {row["id"] for row in second["rows"]})
        ids = self.inv.search("", min_severity=0, ids_only=True, limit=5000)["ids"]
        self.assertEqual(len(ids), first["total"])

    def test_the_time_strip_counts_the_hits(self):
        result = self.inv.search(S.ALPHA)
        histogram = result["histogram"]
        timed = [row for row in self.inv.search(S.ALPHA, limit=1000)["rows"] if row["ts"] is not None]
        self.assertEqual(sum(sum(bucket) for bucket in histogram["counts"]), len(timed))
        self.assertGreater(sum(bucket[DIRECT] for bucket in histogram["counts"]), 0)
        self.assertGreater(sum(bucket[STRONG] for bucket in histogram["counts"]), 0)


class FallbackSearchTest(unittest.TestCase):
    def test_search_works_without_the_text_index(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(investigate, "FTS", False):
            root = Path(folder)
            S.write_samples(root / "logs")
            inv = investigate.create_investigation(root / "inv", "Ohne FTS")
            inv.import_paths([str(root / "logs")])
            with inv.connect() as db:
                self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name = 'events_fts'").fetchone())
            self.assertEqual(inv.search("View=Main", min_severity=0)["total"], 1)
            self.assertEqual(inv.search("SELECT Archiv", min_severity=0)["total"], 1)
            self.assertEqual(inv.search(S.ALPHA)["mode"], "trace")


class ExportTest(SampleInvestigation):
    def alpha_events(self):
        return self.inv.search(S.ALPHA, ids_only=True, min_severity=0)["ids"]

    def test_no_original_value_and_no_file_name_is_left(self):
        result = self.inv.export_text(self.alpha_events(), Mapping())
        text = result["text"]
        self.assertFalse(result["blocked"], result["leaks"])
        for value in (S.ALPHA, S.BETA, S.CLIENT_IP, S.DEVICE, S.MSGID_IN, "firma.example", "partner.example",
                      "MDaemon-2026", "WebDAV-2026", "AirSync-2026"):
            self.assertNotIn(value, text)
        self.assertRegex(text, r"# Sources: Q1 = [\w-]+ \(")
        self.assertIn("MDaemon-IMAP (MDaemon-Ereignisprotokoll)", text)
        self.assertEqual(result["events"], len(self.alpha_events()))

    def test_placeholders_are_consistent_and_those_of_the_store(self):
        mapping = Mapping()
        known = Anonymizer(mapping, Options()).process_line(f"Login {S.ALPHA}")
        placeholder = known.split()[-1]
        result = self.inv.export_text(self.alpha_events(), mapping)
        self.assertGreaterEqual(result["text"].count(placeholder), 5)
        lines = [line for line in result["text"].split("\n") if "Authenticated as" in line]
        self.assertTrue(lines and all(line.endswith(placeholder) for line in lines))

    def test_values_hidden_by_their_surroundings_are_replaced(self):
        result = self.inv.export_text([self.event("AirSync-2026-10-21.log", 1), self.event("RTCServer-2026-10-21.log", 1)], Mapping())
        self.assertNotIn(S.ALPHA, result["text"])
        self.assertNotIn(S.CLIENT_IP, result["text"])
        self.assertNotIn(S.DEVICE, result["text"])
        self.assertIn("QS:Cmd=Sync&User=", result["text"])
        self.assertFalse(result["blocked"])

    def test_a_value_that_remains_blocks_the_export(self):
        with mock.patch.object(investigate, "_sweep", lambda text, candidates, engine: text), \
                mock.patch.object(investigate, "Options", lambda **kwargs: Options()):
            result = self.inv.export_text([self.event("AirSync-2026-10-21.log", 1)], Mapping())
        self.assertTrue(result["blocked"])
        self.assertIn(S.DEVICE, {leak["value"] for leak in result["leaks"]})
        self.assertTrue(any(mark["leak"] and mark["category"] == "Leak" for mark in result["marks"]))

    def test_suspicious_words_need_a_review(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "Relay-2026-10-21.log"
            path.write_text("2026-10-21T08:00:00+02:00 login failed, password=Sommer2026 rejected\n", encoding="utf-8")
            inv = investigate.create_investigation(Path(folder) / "inv", "Prüfen")
            inv.import_paths([str(path)])
            result = inv.export_text(inv.search("", ids_only=True, min_severity=0)["ids"], Mapping())
        self.assertTrue(result["needsReview"])
        self.assertTrue(result["review"])

    def test_a_value_on_the_never_replace_list_stays(self):
        mapping = Mapping()
        mapping.ignore(S.CLIENT_IP)
        result = self.inv.export_text([self.event(IMAP, 3)], mapping)
        self.assertIn(f"from {S.CLIENT_IP}:", result["text"])
        self.assertFalse(result["blocked"])

    def test_nothing_chosen_is_an_error(self):
        with self.assertRaises(investigate.InvestigationError):
            self.inv.export_text([], Mapping())


class EntityTest(unittest.TestCase):
    def kinds(self, text):
        return {(item.kind, item.value) for item in entities.extract(text)}

    def test_a_message_id_is_known_by_its_label(self):
        found = self.kinds("* Message-ID: <synth.0009@partner.example>")
        self.assertIn(("msgid", "synth.0009@partner.example"), found)
        self.assertNotIn(("email", "synth.0009@partner.example"), found)
        self.assertIn(("msgid", "x.1@firma.example"), self.kinds("spamd: processing message <x.1@firma.example> for x"))

    def test_addresses_ports_and_mapped_addresses(self):
        found = self.kinds("from 198.51.100.20:51744 to [2001:db8::5]:993 via ::ffff:203.0.113.7")
        self.assertIn(("ipv4", "198.51.100.20"), found)
        self.assertIn(("endpoint", "198.51.100.20:51744"), found)
        self.assertIn(("ipv6", "2001:db8::5"), found)
        self.assertIn(("endpoint", "[2001:db8::5]:993"), found)
        self.assertIn(("ipv4", "203.0.113.7"), found)

    def test_a_product_version_is_no_address(self):
        found = self.kinds("Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36 from 203.0.113.9")
        self.assertNotIn(("ipv4", "120.0.0.0"), found)
        self.assertIn(("ipv4", "203.0.113.9"), found)

    def test_file_names_and_glued_sentences_are_no_domains(self):
        found = self.kinds("GET /favicon.ico and service.dll, Task 30927.Regards, host mail.firma.example")
        domains = {value for kind, value in found if kind == "domain"}
        self.assertEqual(domains, {"mail.firma.example"})

    def test_a_mail_address_without_what_stands_before_it(self):
        found = self.kinds("QS:Cmd=Sync&User=alpha@firma.example&DeviceId=X")
        self.assertIn(("email", "alpha@firma.example"), found)

    def test_queue_files_urls_and_their_normal_form(self):
        found = self.kinds(r"c:\mdaemon\queues\MD50000000002.MSG and https://mail.firma.example/x?y=1.")
        self.assertIn(("queue", "md50000000002.msg"), found)
        self.assertIn(("url", "https://mail.firma.example/x?y=1"), found)

    def test_system_values_are_generic(self):
        self.assertTrue(entities.is_generic("email", "postmaster@firma.example"))
        self.assertTrue(entities.is_generic("ipv4", "127.0.0.1"))
        self.assertTrue(entities.is_generic("endpoint", "127.0.0.1:783"))
        self.assertFalse(entities.is_generic("email", S.ALPHA))
        login = entities.explicit("account", "Alpha@Firma.example")
        self.assertEqual((login.kind, login.value, login.role), ("email", S.ALPHA, "account"))
        self.assertEqual(entities.explicit("account", "jdoe").kind, "account")

    def test_a_new_kind_of_identifier_needs_one_rule(self):
        rule = entities.Rule("code", re.compile(r"\bTKT-\d{5}\b"), priority=60)
        entities.register(rule)
        try:
            self.assertIn(("code", "TKT-12345"), self.kinds("Ticket TKT-12345 opened"))
        finally:
            entities.RULES.remove(rule)


class EntityDetailTest(SampleInvestigation):
    def test_the_explorer_shows_files_roles_and_relations(self):
        alpha = self.entity("email", S.ALPHA)
        detail = self.inv.entity_detail(alpha)
        self.assertEqual(detail["kind"], "email")
        self.assertEqual(detail["sources"], len(detail["bySource"]))
        self.assertIn("to", detail["roles"])
        related = {item["value"] for item in detail["related"]}
        self.assertTrue({S.CLIENT_IP, S.DEVICE, S.MSGID_IN} <= related)
        self.assertGreater(detail["levels"]["stark"], 0)
        self.assertIn(S.CLIENT_IP, {item["value"] for item in detail["possible"]})

    def test_the_graph_has_the_value_its_neighbours_and_weighted_edges(self):
        alpha = self.entity("email", S.ALPHA)
        graph = self.inv.graph(alpha)
        self.assertEqual(graph["anchor"], alpha)
        values = {node["value"] for node in graph["nodes"]}
        self.assertTrue({S.ALPHA, S.CLIENT_IP, S.DEVICE} <= values)
        self.assertTrue(all(edge["weight"] >= 1 for edge in graph["edges"]))
        only_devices = self.inv.graph(alpha, kinds=["device"])
        self.assertEqual({node["kind"] for node in only_devices["nodes"] if not node.get("anchor")}, {"device"})

    def test_an_event_shows_its_lines_values_and_time(self):
        detail = self.inv.event_detail(self.event(IMAP, 5))
        self.assertEqual(detail["contextNote"], "")
        self.assertEqual([line["line"] for line in detail["contextLines"]], list(range(1, 12)))
        self.assertEqual([line["line"] for line in detail["contextLines"] if line["own"]], [5])
        self.assertIn(S.ALPHA, {span["value"] for span in detail["spans"]})
        self.assertEqual(detail["timeFlag"], "inferred")
        self.assertTrue(detail["wall"].startswith("2026-10-21 08:05:00"))
        self.assertTrue(detail["contextLabel"].startswith("Sitzung 00000001"))
        with self.assertRaises(investigate.InvestigationError):
            self.inv.event_detail(10 ** 9)


class LargeTest(unittest.TestCase):
    def test_tens_of_thousands_of_lines_stay_fast(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = S.large_log(root / "MDaemon-2026-10-21-IMAP.log", sessions=4000)
            inv = investigate.create_investigation(root / "inv", "Gross")
            progress = []
            started = time.perf_counter()
            report = inv.import_paths([str(path)], progress=lambda value, name="": progress.append(value))
            imported = time.perf_counter() - started
            self.assertEqual(len(report["imported"]), 1)
            self.assertTrue(progress and progress[-1] >= 0.99)
            self.assertLess(imported, 60)
            with inv.connect() as db:
                sessions = db.execute("SELECT COUNT(*) FROM entities WHERE kind = 'session'").fetchone()[0]
            self.assertEqual(sessions, 4000)
            started = time.perf_counter()
            result = inv.search("konto007@firma.example")
            self.assertLess(time.perf_counter() - started, 5)
            self.assertEqual(result["mode"], "trace")
            self.assertEqual(result["levels"]["direkt"], 20 * 7)
            started = time.perf_counter()
            text = inv.search("SELECT", min_severity=0, limit=50)
            self.assertLess(time.perf_counter() - started, 2)
            self.assertEqual(text["total"], 4000)
            self.assertEqual(len(text["rows"]), 50)

    def test_cancelling_keeps_what_was_read(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            S.write_samples(root / "logs")
            S.large_log(root / "logs" / "MDaemon-2026-10-21-IMAP-gross.log", sessions=3000)
            inv = investigate.create_investigation(root / "inv", "Abbruch")
            calls = []

            def cancelled():
                calls.append(1)
                return len(calls) > 3

            report = inv.import_paths([str(root / "logs")], cancelled=cancelled)
            self.assertTrue(report.get("cancelled"))
            overview = inv.overview()
            self.assertLess(len(overview["sources"]), len(S.SAMPLES) + 1)
            with inv.connect() as db:
                untimed = db.execute("SELECT COUNT(*) FROM events WHERE wall_ms IS NOT NULL AND ts_ms IS NULL").fetchone()[0]
            self.assertEqual(untimed, 0)


class PersistenceTest(unittest.TestCase):
    def test_an_investigation_survives_reopening_and_can_be_deleted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            logs = S.write_samples(root / "logs")
            inv = investigate.create_investigation(root / "inv", "Fall 1/Teil a")
            inv.import_paths([str(logs[IMAP]), str(logs["AirSync-2026-10-21.log"])])
            client = inv.find_entities(S.CLIENT_IP)[0]["id"]
            inv.flag_entity(client, "exclude")
            listed = investigate.list_investigations(root / "inv")
            self.assertEqual([(item["id"], item["name"], item["sources"]) for item in listed], [(inv.id, "Fall 1/Teil a", 2)])
            self.assertTrue(re.fullmatch(r"Fall-1-Teil-a-[0-9a-f]{8}", inv.id))
            again = investigate.Investigation(investigate.investigation_path(root / "inv", inv.id))
            self.assertEqual(again.overview()["counts"], inv.overview()["counts"])
            self.assertEqual(again.search(S.ALPHA)["total"], inv.search(S.ALPHA)["total"])
            self.assertTrue(again.entity_detail(client)["excluded"])
            investigate.delete_investigation(root / "inv", inv.id)
            self.assertEqual(investigate.list_investigations(root / "inv"), [])
            self.assertEqual(list((root / "inv").iterdir()), [])
            with self.assertRaises(investigate.InvestigationError):
                investigate.investigation_path(root / "inv", inv.id)
            with self.assertRaises(investigate.InvestigationError):
                investigate.investigation_path(root / "inv", "../logs/etwas")

    def test_removing_a_file_takes_its_events_and_values_along(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            logs = S.write_samples(root / "logs")
            inv = investigate.create_investigation(root / "inv", "Entfernen")
            inv.import_paths([str(logs[IMAP]), str(logs["AirSync-2026-10-21.log"])])
            airsync = next(item["id"] for item in inv.overview()["sources"] if item["name"] == "AirSync-2026-10-21.log")
            inv.remove_source(airsync)
            self.assertEqual([item["name"] for item in inv.overview()["sources"]], [IMAP])
            self.assertEqual(inv.find_entities(S.DEVICE), [])
            self.assertEqual(inv.search(S.DEVICE, min_severity=0)["total"], 0)
            self.assertTrue(inv.search(S.ALPHA)["rows"])
            with inv.connect() as db:
                orphans = db.execute(
                    "SELECT COUNT(*) FROM entities WHERE NOT EXISTS "
                    "(SELECT 1 FROM occurrences o WHERE o.entity_id = entities.id)"
                ).fetchone()[0]
            self.assertEqual(orphans, 0)


class ScanTest(unittest.TestCase):
    def test_the_scan_reads_head_and_tail_and_groups_by_log_type(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            logs = S.write_samples(root / "logs")
            S.large_log(root / "logs" / "MDaemon-2026-10-22-IMAP.log", sessions=300, day="2026-10-22")
            inv = investigate.create_investigation(root / "inv", "Scan")
            inv.import_paths([str(logs["HTTP-2026-10-21.log"])])
            before = {name: _fingerprint(path) for name, path in logs.items()}
            progress = []
            scan = inv.scan_paths([str(root / "logs")], progress=lambda value, name="": progress.append(value))
            self.assertEqual({name: _fingerprint(path) for name, path in logs.items()}, before)
            self.assertTrue(scan["complete"])
            self.assertEqual(len(scan["files"]), len(S.SAMPLES) + 1)
            self.assertEqual(scan["size"], sum(path.stat().st_size for path in (root / "logs").iterdir()))
            files = {item["name"]: item for item in scan["files"]}
            imap = files[IMAP]
            self.assertEqual((imap["kind"], imap["day"], imap["format"], imap["encoding"]),
                             ("MDaemon-IMAP", "2026-10-21", "mdaemon", "utf-8"))
            self.assertEqual((imap["first"], imap["last"][:16]), ("2026-10-21 08:05:00", "2026-10-21 13:00"))
            self.assertFalse(imap["imported"])
            self.assertTrue(files["HTTP-2026-10-21.log"]["imported"])
            self.assertEqual(files["MDaemon-2026-10-21-RAW.log"]["encoding"], "cp1252")
            groups = {group["kind"]: group for group in scan["groups"]}
            self.assertEqual(groups["MDaemon-IMAP"]["files"], 2)
            self.assertEqual(groups["MDaemon-IMAP"]["formats"], ["MDaemon-Ereignisprotokoll"])
            self.assertEqual(groups["HTTP"]["imported"], 1)
            self.assertTrue(progress)
            # Nothing was indexed by the scan.
            self.assertEqual([item["name"] for item in inv.overview()["sources"]], ["HTTP-2026-10-21.log"])

    def test_the_scan_stops_when_cancelled_and_says_so(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            S.write_samples(root / "logs")
            inv = investigate.create_investigation(root / "inv", "Scan")
            calls = []

            def cancelled():
                calls.append(1)
                return len(calls) > 3

            scan = inv.scan_paths([str(root / "logs")], cancelled=cancelled)
            self.assertFalse(scan["complete"])
            self.assertLess(len(scan["files"]), len(S.SAMPLES))
            with self.assertRaises(investigate.InvestigationError):
                inv.scan_paths([str(root / "leer")])

    def test_log_types_are_named_without_their_dates(self):
        self.assertEqual(investigate.source_kind("MDaemon-2026-10-21-AntiVirus.log"), "MDaemon-AntiVirus")
        self.assertEqual(investigate.source_kind("AirSync-2026-10-21.log"), "AirSync")
        self.assertEqual(investigate.source_kind(r"C:\MDaemon\Logs\WebDAV-2026-10-21.log"), "WebDAV")


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.logs = S.write_samples(self.root / "logs")
        S.large_log(self.root / "logs" / "MDaemon-2026-10-21-IMAP-gross.log", sessions=3000)
        self.inv = investigate.create_investigation(self.root / "inv", "Plan")

    def tearDown(self):
        self.tmp.cleanup()

    def names(self):
        return {item["name"] for item in self.inv.overview()["sources"]}

    def test_priority_files_are_ready_and_searchable_before_the_background(self):
        priority = [str(self.logs[name]) for name in ("WebDAV-2026-10-21.log", "AirSync-2026-10-21.log")]
        seen = {}

        def ready():
            seen["names"] = self.names()
            seen["search"] = self.inv.search(S.ALPHA)

        phases = []
        report = self.inv.import_plan(
            priority, [str(self.root / "logs")], ready=ready,
            status=lambda detail: phases.append(detail["phase"]),
        )
        self.assertEqual(seen["names"], {"WebDAV-2026-10-21.log", "AirSync-2026-10-21.log"})
        self.assertEqual(seen["search"]["mode"], "trace")
        self.assertTrue(seen["search"]["rows"])
        self.assertEqual(phases[-1], "done")
        self.assertLess(phases.index("priority"), phases.index("background"))
        # Priority files are not read twice although their folder is in the background list.
        self.assertEqual(len(report["imported"]), len(S.SAMPLES) + 1)
        self.assertEqual(report["duplicates"], [])

    def test_cancelling_in_the_background_keeps_the_finished_files(self):
        priority = [str(self.logs["HTTP-2026-10-21.log"])]
        state = {"ready": False, "calls": 0}

        def cancelled():
            if state["ready"]:
                state["calls"] += 1
            return state["calls"] > 2

        report = self.inv.import_plan(
            priority, [str(self.root / "logs" / "MDaemon-2026-10-21-IMAP-gross.log")],
            cancelled=cancelled, ready=lambda: state.update(ready=True),
        )
        self.assertTrue(report.get("cancelled"))
        self.assertEqual(self.names(), {"HTTP-2026-10-21.log"})
        with self.inv.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sources WHERE state != 'ready'").fetchone()[0], 0)
            orphans = db.execute(
                "SELECT COUNT(*) FROM entities WHERE NOT EXISTS (SELECT 1 FROM occurrences o WHERE o.entity_id = entities.id)"
            ).fetchone()[0]
            self.assertEqual(orphans, 0)
            self.assertEqual(*_text_index(db))

    def test_a_large_file_is_searchable_while_it_is_read(self):
        seen = []

        def status(detail):
            if detail["phase"] == "background" and detail["bytes"] > 300_000 and not seen:
                seen.append(self.inv.search("SELECT", min_severity=0)["total"])

        with mock.patch.object(investigate, "COMMIT_EVERY", 2000):
            self.inv.import_plan([], [str(self.root / "logs" / "MDaemon-2026-10-21-IMAP-gross.log")], status=status)
        self.assertTrue(seen and 0 < seen[0] < 3000)
        self.assertEqual(self.inv.search("SELECT", min_severity=0)["total"], 3000)


def _snapshot(inv):
    with inv.connect() as db:
        return [tuple(row) for row in db.execute(
            "SELECT kind, value, events, groups, sources, first_ms, last_ms, common FROM entities ORDER BY kind, value"
        )]


def _full(inv):
    """The entity counts after counting everything again, as the incremental ones must be."""
    with inv.connect() as db:
        inv._entity_stats(db, None)
    return _snapshot(inv)


class IncrementalStatsTest(unittest.TestCase):
    def test_counts_per_file_add_up_to_a_full_recount(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            logs = S.write_samples(root / "logs")
            inv = investigate.create_investigation(root / "inv", "Zähler")
            for name in (IMAP, "AirSync-2026-10-21.log", "WebDAV-2026-10-21.log", "MDaemon-2026-10-21-RAW.log"):
                inv.import_paths([str(logs[name])])
                self.assertEqual(_snapshot(inv), _full(inv), name)
            inv.import_paths([str(root / "logs")])
            self.assertEqual(_snapshot(inv), _full(inv))
            inv.set_time(None, "fixed", 60)
            self.assertEqual(_snapshot(inv), _full(inv))
            for source in inv.overview()["sources"][::3]:
                inv.remove_source(source["id"])
                self.assertEqual(_snapshot(inv), _full(inv), source["name"])

    def test_a_value_becomes_frequent_and_ordinary_again(self):
        def virus_log(path, numbers):
            lines = []
            for number in numbers:
                stamp = f"Wed 2026-10-21 08:{number // 60:02d}:{number % 60:02d}"
                lines += [
                    f"{stamp}.000: MDaemon AntiVirus processing md5{number:010d}.msg...",
                    f"{stamp}.010: * Message-ID: <always.the.same@firma.example>",
                    f"{stamp}.020: ----------",
                ]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return path

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            limit = investigate.COMMON_MIN_GROUPS
            first = virus_log(root / "a" / "MDaemon-2026-10-21-AntiVirus.log", range(limit - 10))
            second = virus_log(root / "b" / "MDaemon-2026-10-21-AntiVirus.log", range(limit - 10, limit + 5))
            inv = investigate.create_investigation(root / "inv", "Häufig")
            inv.import_paths([str(first)])
            msgid = inv.find_entities("always.the.same@firma.example")[0]
            self.assertEqual((msgid["groups"], msgid["common"]), (limit - 10, False))
            inv.import_paths([str(second)])
            msgid = inv.find_entities("always.the.same@firma.example")[0]
            self.assertEqual((msgid["groups"], msgid["common"]), (limit + 5, True))
            self.assertEqual(_snapshot(inv), _full(inv))
            inv.remove_source(next(item["id"] for item in inv.overview()["sources"] if item["path"] == str(second)))
            self.assertFalse(inv.find_entities("always.the.same@firma.example")[0]["common"])
            self.assertEqual(_snapshot(inv), _full(inv))


class ContextTest(unittest.TestCase):
    def test_the_lines_around_an_event_come_from_the_original(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = S.large_log(root / "MDaemon-2026-10-21-IMAP.log", sessions=500)
            inv = investigate.create_investigation(root / "inv", "Kontext")
            inv.import_paths([str(path)])
            original = path.read_text(encoding="utf-8").splitlines()
            with inv.connect() as db:
                event_id, start = db.execute(
                    f"SELECT id, line_start FROM events e WHERE {TEXT} LIKE '%c333 SELECT%'"
                ).fetchone()
            detail = inv.event_detail(event_id)
            self.assertEqual(detail["contextNote"], "")
            for line in detail["contextLines"]:
                self.assertEqual(line["text"], original[line["line"] - 1])
            self.assertEqual([line["line"] for line in detail["contextLines"]], list(range(start - 6, start + 7)))
            # A changed file is not trusted: the stored lines stand in, with a note.
            with open(path, "a", encoding="utf-8") as handle:
                handle.write("Wed 2026-10-21 23:59:59.000: angehängt\n")
            changed = inv.event_detail(event_id)
            self.assertTrue(changed["contextNote"])
            self.assertIn("c333 SELECT", "\n".join(line["text"] for line in changed["contextLines"] if line["own"]))

    def test_the_byte_reader_counts_lines_like_the_text_reader(self):
        import random

        random.seed(3)
        with tempfile.TemporaryDirectory() as folder:
            name = Path(folder) / "x.log"
            for _ in range(200):
                text = "".join(random.choice(["a", "ä", "\r", "\n", "\r\n", " ", "€"]) for _ in range(random.randint(0, 40)))
                for encoding in ("utf-8", "cp1252", "utf-8-sig"):
                    name.write_bytes(text.encode(encoding))
                    expected = list(logformats.read_lines(name, encoding))
                    with open(name, "rb") as handle:
                        pairs = list(logformats.read_raw_lines(
                            handle, chunk_size=random.choice([1, 3, 64]), bom=logformats.bom_of(encoding)))
                    self.assertEqual([raw.decode(encoding, "replace") for _, raw in pairs], expected)
                    data = name.read_bytes()
                    self.assertTrue(all(data[offset:offset + len(raw)] == raw for offset, raw in pairs))


class LargeViewTest(unittest.TestCase):
    def test_many_hits_get_a_binned_time_strip_and_a_fast_first_page(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = S.large_log(root / "MDaemon-2026-10-21-IMAP.log", sessions=1500)
            inv = investigate.create_investigation(root / "inv", "Viel")
            inv.import_paths([str(path)])
            with mock.patch.object(investigate, "COUNT_CAP", 500):
                result = inv.search("", min_severity=0)
                self.assertEqual(result["total"], 501)
                self.assertTrue(result["histogram"]["approximate"])
                self.assertEqual(sum(bucket[0] for bucket in result["histogram"]["counts"]), 1500 * 7 + 1 - 1)
                self.assertEqual(result["histogram"]["bucketMs"] % investigate.BIN_MS, 0)
                # Text with very many hits goes without the strip instead of scanning everything.
                self.assertIsNone(inv.search("SELECT", min_severity=0)["histogram"])
            stamps = [row["ts"] for row in result["rows"]]
            self.assertEqual(stamps, sorted(stamps))


class UpgradeTest(unittest.TestCase):
    def test_an_investigation_of_the_first_version_is_brought_up_to_date(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            logs = S.write_samples(root / "logs")
            inv = investigate.create_investigation(root / "inv", "Alt")
            inv.import_paths([str(logs["HTTP-2026-10-21.log"]), str(logs["WebDAV-2026-10-21.log"])])
            expected = _snapshot(inv)
            # Back to the first layout: no sort key, no per-file statistics, no marks.
            with inv.connect() as db:
                db.execute("DROP INDEX events_sort")
                db.execute("ALTER TABLE events DROP COLUMN sort_ms")
                for column in ("time_flags", "etypes", "stated", "state", "mtime_ns"):
                    db.execute(f"ALTER TABLE sources DROP COLUMN {column}")
                for table in ("entity_source", "ip_accounts", "bins", "marks"):
                    db.execute(f"DELETE FROM {table}")
                db.execute("DELETE FROM meta WHERE key = 'stats_version'")
                db.execute("CREATE INDEX events_ts ON events(ts_ms)")
                # The first version kept the context key itself on every event.
                db.execute("UPDATE events SET ctx = (SELECT key FROM contexts WHERE id = events.ctx) WHERE ctx IS NOT NULL")
                db.execute("DELETE FROM contexts")
                # It kept the text on every event, with a text index referring to it.
                db.execute(f"UPDATE events AS e SET message = {TEXT}")
                db.execute("DELETE FROM texts")
                db.execute("DROP INDEX events_ctx")
                db.execute("CREATE INDEX events_ctx ON events(ctx)")
                if investigate.FTS:
                    db.execute("DROP TABLE events_fts")
                    db.execute(
                        "CREATE VIRTUAL TABLE events_fts USING fts5(message, content='events', content_rowid='id', "
                        "detail=none, columnsize=0)"
                    )
                    db.execute("INSERT INTO events_fts(events_fts) VALUES ('rebuild')")
                event_id = db.execute(
                    "SELECT id FROM events WHERE message LIKE ?", (f"%Authenticate: {S.ALPHA}%",)
                ).fetchone()[0]
            again = investigate.Investigation(inv.path)
            detail = again.event_detail(event_id)
            self.assertTrue(detail["contextLabel"].startswith("Request BCDEFGHJKL"))
            self.assertEqual(len(again.context_events(event_id)), 2)
            overview = again.overview()
            self.assertEqual(len(overview["sources"]), 2)
            self.assertTrue(all(source["timeFlags"] for source in overview["sources"]))
            self.assertTrue(again.search(S.ALPHA)["rows"])
            stamps = [row["ts"] for row in again.search("", min_severity=0)["rows"]]
            self.assertEqual(stamps, sorted(stamps))
            self.assertEqual(again.search("WorldClient", min_severity=0)["total"], 2)
            again.import_paths([str(logs["AirSync-2026-10-21.log"])])
            with again.connect() as db:
                self.assertEqual(again.meta(db, "stats_version"), str(investigate.STATS_VERSION))
                # Old events keep their text where it was, new ones are in blocks: both are found.
                self.assertEqual(*_text_index(db))
                self.assertTrue(db.execute("SELECT COUNT(*) FROM texts").fetchone()[0])
            snapshot = _snapshot(again)
            self.assertEqual(snapshot, _full(again))
            # What changed are the values the third file shares with the first two.
            changed = {row[1] for row in set(expected) - set(snapshot)}
            self.assertTrue(changed)
            self.assertTrue(changed <= {S.ALPHA, S.CLIENT_IP, "mail.firma.example"}, changed)


class TextBlockTest(unittest.TestCase):
    def texts(self, inv):
        with inv.connect() as db:
            return {(name, start): text for name, start, text in db.execute(
                f"SELECT s.name, e.line_start, {TEXT} FROM events e JOIN sources s ON s.id = e.source_id"
            )}

    def test_texts_are_compressed_and_outlive_a_neighbour_in_their_block(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            logs = S.write_samples(root / "logs")
            S.large_log(root / "logs" / "MDaemon-2026-10-22-IMAP-gross.log", sessions=400)
            inv = investigate.create_investigation(root / "inv", "Text")
            inv.import_paths([str(root / "logs")])
            before = self.texts(inv)
            with inv.connect() as db:
                stored = db.execute("SELECT SUM(LENGTH(data)) FROM texts").fetchone()[0]
                plain = db.execute(f"SELECT SUM(LENGTH(CAST({TEXT} AS BLOB))) FROM events e").fetchone()[0]
                self.assertIsNone(db.execute("SELECT message FROM events WHERE message IS NOT NULL").fetchone())
                # The small files share blocks with each other.
                shared = db.execute(
                    f"SELECT COUNT(*) FROM (SELECT id >> {investigate.TEXT_SHIFT} FROM events "
                    "GROUP BY 1 HAVING COUNT(DISTINCT source_id) > 1)"
                ).fetchone()[0]
            self.assertLess(stored, plain / 3)
            self.assertGreater(shared, 0)
            gone = {"MDaemon-2026-10-21-IMAP.log", "WebDAV-2026-10-21.log"}
            for source in inv.overview()["sources"]:
                if source["name"] in gone:
                    inv.remove_source(source["id"])
            self.assertEqual(self.texts(inv), {key: text for key, text in before.items() if key[0] not in gone})
            with inv.connect() as db:
                self.assertEqual(*_text_index(db))
            for source in inv.overview()["sources"]:
                inv.remove_source(source["id"])
            with inv.connect() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM texts").fetchone()[0], 0)


class ContinuedTest(unittest.TestCase):
    """A growing log copied twice: only the longest copy is read."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.later = S.large_log(self.root / "abends" / "MDaemon-2026-10-21-IMAP.log", sessions=600)
        data = self.later.read_bytes()
        cut = data.index(b"\n", len(data) // 2) + 1
        self.earlier = self.root / "mittags" / "MDaemon-2026-10-21-IMAP.log"
        self.earlier.parent.mkdir()
        self.earlier.write_bytes(data[:cut])
        self.inv = investigate.create_investigation(self.root / "inv", "Fortgeschrieben")

    def tearDown(self):
        self.tmp.cleanup()

    def sources(self, inv=None):
        return [(source["path"], source["events"]) for source in (inv or self.inv).overview()["sources"]]

    def events_of(self, path):
        alone = investigate.create_investigation(self.root / "allein", "Allein")
        alone.import_paths([str(path)])
        return alone.overview()["counts"]["events"]

    def test_an_earlier_copy_in_the_same_import_is_left_out(self):
        seen = []
        report = self.inv.import_plan(
            [str(self.earlier)], [str(self.later)], ready=lambda: seen.append(self.sources()),
        )
        self.assertEqual(report["continued"], [{"path": str(self.earlier), "within": "abends/" + self.later.name}])
        self.assertEqual([item["path"] for item in report["imported"]], [str(self.later)])
        # The longer copy took the place of the priority file it continues.
        self.assertEqual([path for path, _ in seen[0]], [str(self.later)])
        self.assertEqual(self.sources(), [(str(self.later), self.events_of(self.later))])

    def test_an_imported_earlier_copy_is_replaced_with_its_settings_and_decisions(self):
        self.inv.import_paths([str(self.earlier)])
        source_id = self.inv.overview()["sources"][0]["id"]
        self.inv.set_time(source_id, "fixed", 60, 2)
        account = self.inv.find_entities("konto007@firma.example")[0]["id"]
        self.inv.flag_entity(account, "exclude")
        report = self.inv.import_paths([str(self.later)])
        self.assertEqual(report["replaced"], [{"name": self.earlier.name, "by": self.later.name}])
        self.assertEqual(self.sources(), [(str(self.later), self.events_of(self.later))])
        source = self.inv.overview()["sources"][0]
        self.assertEqual((source["tz_mode"], source["tz_offset"], source["skew_ms"]), ("fixed", 60, 2000))
        with self.inv.connect() as db:
            wall, ts = db.execute("SELECT wall_ms, ts_ms FROM events WHERE wall_ms IS NOT NULL LIMIT 1").fetchone()
            self.assertEqual(ts, wall - 60 * 60000 + 2000)
            self.assertEqual([row[0] for row in db.execute("SELECT entity_id FROM excluded")], [account])
            self.assertEqual(*_text_index(db))
        self.assertEqual(self.inv.find_entities("konto007@firma.example")[0]["id"], account)

    def test_a_later_copy_in_the_index_leaves_an_earlier_one_out(self):
        self.inv.import_paths([str(self.later)])
        report = self.inv.import_paths([str(self.earlier)])
        self.assertEqual(report["continued"], [{"path": str(self.earlier), "within": "abends/" + self.later.name}])
        self.assertEqual(report["imported"], [])
        self.assertEqual([path for path, _ in self.sources()], [str(self.later)])

    def test_a_log_that_grew_where_it_was_read_replaces_what_was_read(self):
        live = self.root / "live" / "MDaemon-2026-10-21-IMAP.log"
        live.parent.mkdir()
        live.write_bytes(self.earlier.read_bytes())
        self.inv.import_paths([str(live)])
        live.write_bytes(self.later.read_bytes())
        report = self.inv.import_paths([str(live)])
        self.assertEqual(report["replaced"], [{"name": live.name, "by": live.name}])
        self.assertEqual(self.sources(), [(str(live), self.events_of(self.later))])

    def test_files_that_only_begin_alike_are_both_read(self):
        other = self.root / "anders" / "MDaemon-2026-10-21-IMAP.log"
        other.parent.mkdir()
        data = self.earlier.read_bytes()
        other.write_bytes(data[:4000] + data[4000:].replace(b"SELECT INBOX", b"SELECT Archiv") + b"x\n")
        report = self.inv.import_paths([str(self.earlier), str(other)])
        self.assertEqual(report["continued"], [])
        self.assertEqual(len(report["imported"]), 2)

    def test_the_scan_shows_earlier_copies_and_what_a_file_replaces(self):
        scan = self.inv.scan_paths([str(self.root / "mittags"), str(self.root / "abends")])
        marks = {item["path"]: (item.get("within"), item.get("replaces")) for item in scan["files"]}
        self.assertEqual(marks[str(self.earlier)], ("abends/" + self.later.name, None))
        self.assertEqual(marks[str(self.later)], (None, None))
        self.assertEqual(scan["groups"][0]["within"], 1)
        self.assertNotIn("key", scan["files"][0])
        self.inv.import_paths([str(self.earlier)])
        scan = self.inv.scan_paths([str(self.root / "abends")])
        self.assertEqual(scan["files"][0]["replaces"], ["mittags/" + self.earlier.name])

    def test_helper_processes_replace_and_leave_out_the_same(self):
        self.inv.import_paths([str(self.earlier)])
        third = self.root / "spaet" / "MDaemon-2026-10-21-IMAP.log"
        third.parent.mkdir()
        third.write_bytes(self.later.read_bytes() + b"Wed 2026-10-21 23:59:59.000: ----------\n")
        with mock.patch.dict(os.environ, {"LOGMASQUE_IMPORT_READERS": "2"}):
            report = self.inv.import_plan([str(self.later)], [str(third)])
        self.assertEqual(report["readers"], {"count": 1})
        self.assertEqual(report["continued"], [{"path": str(self.later), "within": "spaet/" + third.name}])
        self.assertEqual(report["replaced"], [{"name": self.earlier.name, "by": third.name}])
        self.assertEqual(self.sources(), [(str(third), self.events_of(third))])

    def test_decisions_about_values_that_are_gone_go_with_them(self):
        self.inv.import_paths([str(self.earlier)])
        with self.inv.connect() as db:
            session = db.execute("SELECT id FROM entities WHERE kind = 'session' LIMIT 1").fetchone()[0]
        self.inv.flag_entity(session, "exclude")
        self.inv.remove_source(self.inv.overview()["sources"][0]["id"])
        with self.inv.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM excluded").fetchone()[0], 0)


TEXT_WORDS = ("select", "session", "authenticated", "imap", "get", "http", "complete", "accepting", "message", "error")


def _text_index(db):
    """Per word: events the text index finds, and events whose text holds it; both must agree."""
    if not investigate.FTS:
        return {}, {}
    found = {word: db.execute("SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH ?", (word,)).fetchone()[0]
             for word in TEXT_WORDS}
    texts = [row[0] for row in db.execute(f"SELECT {TEXT} FROM events e")]
    held = {word: sum(1 for text in texts if word in set(re.findall(r"[^\W_]+", text.lower()))) for word in TEXT_WORDS}
    return found, held


def _content(inv):
    """Everything an import writes, by file name and line instead of by number.

    Numbers of files, events, contexts and entities depend on the order the
    files are written in; what they stand for must not.
    """
    with inv.connect() as db:
        names = dict(db.execute("SELECT id, name FROM sources"))

        def named(text):
            head, _, rest = (text or "").partition(":")
            return f"{names[int(head)]}:{rest}" if head.isdigit() and int(head) in names else text

        def rows(sql, *keyed, parsed=()):
            return sorted(
                tuple(
                    named(value) if index in keyed else json.loads(value or "null") if index in parsed else value
                    for index, value in enumerate(row)
                )
                for row in db.execute(sql)
            )

        return {
            "sources": rows(
                "SELECT name, parser, parser_label, encoding, size, sha256, lines, events, first_ms, last_ms, "
                "detected_offset, stated, etypes, time_flags, state FROM sources", parsed=(11, 12, 13)
            ),
            "events": rows(
                "SELECT s.name, e.line_start, e.line_end, e.wall_ms, e.line_off, e.raw_flag, e.off_min, e.ts_ms, "
                f"e.ts_flag, e.etype, e.severity, c.key, {TEXT}, e.sort_ms FROM events e "
                "JOIN sources s ON s.id = e.source_id LEFT JOIN contexts c ON c.id = e.ctx", 11
            ),
            "occurrences": rows(
                "SELECT s.name, e.line_start, n.kind, n.value, o.role FROM occurrences o "
                "JOIN entities n ON n.id = o.entity_id JOIN events e ON e.id = o.event_id "
                "JOIN sources s ON s.id = e.source_id", 3
            ),
            "entities": rows(
                "SELECT kind, value, display, events, groups, sources, first_ms, last_ms, common, generic "
                "FROM entities", 1
            ),
            "entity_source": rows(
                "SELECT n.kind, n.value, s.name, x.events, x.groups, x.first_ms, x.last_ms FROM entity_source x "
                "JOIN entities n ON n.id = x.entity_id JOIN sources s ON s.id = x.source_id", 1
            ),
            "ip_accounts": rows(
                "SELECT a.value, b.value, s.name FROM ip_accounts x JOIN entities a ON a.id = x.ip_id "
                "JOIN entities b ON b.id = x.account_id JOIN sources s ON s.id = x.source_id"
            ),
            "marks": rows("SELECT s.name, m.lineno, m.offset FROM marks m JOIN sources s ON s.id = m.source_id"),
            "bins": rows("SELECT s.name, b.bin, b.severity, b.n FROM bins b JOIN sources s ON s.id = b.source_id"),
            "contexts": len(db.execute("SELECT id FROM contexts").fetchall()),
            "text": _text_index(db),
        }


class ParallelTest(unittest.TestCase):
    """Helper processes read and parse; the index must be the one a single process writes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        logs = S.write_samples(self.root / "logs")
        S.large_log(self.root / "logs" / "MDaemon-2026-10-21-IMAP-gross.log", sessions=1500)
        S.large_log(self.root / "logs" / "MDaemon-2026-10-22-IMAP-gross.log", sessions=1400, day="2026-10-22")
        (self.root / "logs" / "MDaemon-2026-10-23-IMAP.log").write_bytes(S.imap_log().encode("utf-16"))
        shutil.copy(logs["WebDAV-2026-10-21.log"], self.root / "logs" / "WebDAV-Kopie.log")
        self.priority = [str(logs["AirSync-2026-10-21.log"]), str(self.root / "logs" / "MDaemon-2026-10-22-IMAP-gross.log")]

    def tearDown(self):
        self.tmp.cleanup()

    def run_import(self, name, readers, **patches):
        inv = investigate.create_investigation(self.root / name, name)
        ready = []
        self.statuses = []
        with mock.patch.dict(os.environ, {"LOGMASQUE_IMPORT_READERS": str(readers)}):
            with mock.patch.object(investigate, "COMMIT_EVERY", 4000):
                report = inv.import_plan(
                    self.priority, [str(self.root / "logs")], ready=lambda: ready.append(inv.overview()),
                    status=lambda detail: self.statuses.append(dict(detail)), **patches,
                )
        return inv, report, ready

    def test_the_index_is_the_same_with_helper_processes(self):
        alone, report, ready = self.run_import("alone", 0)
        self.assertNotIn("readers", report)
        helped, helped_report, helped_ready = self.run_import("helped", 3)
        self.assertEqual(helped_report["readers"], {"count": 3})
        self.assertEqual(len(helped_report["imported"]), len(report["imported"]))
        self.assertEqual(helped_report["duplicates"], report["duplicates"])
        self.assertEqual(len(report["duplicates"]), 1)
        self.assertEqual(helped_report["failed"], [])
        self.assertEqual(_content(helped), _content(alone))
        for text in (S.ALPHA, "SELECT", "konto007@firma.example", S.MSGID_IN):
            self.assertEqual(helped.search(text, min_severity=0)["total"], alone.search(text, min_severity=0)["total"])
        # Files are counted against all files of the plan, duplicates included.
        self.assertTrue(all(detail["files"] <= detail["filesTotal"] for detail in self.statuses))
        self.assertEqual((self.statuses[-1]["files"], self.statuses[-1]["filesTotal"]), (len(S.SAMPLES) + 4,) * 2)
        # The priority files were ready first, with the helpers as well.
        self.assertEqual(len(helped_ready), 1)
        self.assertTrue({"AirSync-2026-10-21.log", "MDaemon-2026-10-22-IMAP-gross.log"}
                        <= {source["name"] for source in helped_ready[0]["sources"] if source["state"] == "ready"})

    def test_files_left_by_failing_helpers_are_read_here(self):
        alone, _, _ = self.run_import("alone", 0)
        real_next = investigate._Readers.next
        taken = []

        def next_message(pool, timeout=0.5):
            if len(taken) >= 40:
                return None
            message = real_next(pool, timeout)
            if message is not None:
                taken.append(message[0])
            return message

        with mock.patch.object(investigate._Readers, "next", next_message), \
                mock.patch.object(investigate._Readers, "lost", lambda pool: True):
            helped, report, _ = self.run_import("helped", 2)
        self.assertIn("fallback", report["readers"])
        self.assertEqual(report["failed"], [])
        self.assertEqual(_content(helped), _content(alone))

    def test_a_file_failing_in_a_helper_leaves_nothing_behind(self):
        target = "MDaemon-2026-10-21-IMAP-gross.log"
        alone, _, _ = self.run_import("alone", 0)
        alone.remove_source(next(source["id"] for source in alone.overview()["sources"] if source["name"] == target))
        real_init, real_next = investigate._Readers.__init__, investigate._Readers.next

        def init(pool, tasks, count):
            pool.target = next(index for index, name, _ in tasks if name.endswith(target))
            pool.seen = 0
            real_init(pool, tasks, count)

        def next_message(pool, timeout=0.5):
            # The file fails after a part of it is written: its second portion becomes an error.
            while True:
                message = real_next(pool, timeout)
                if message is None or message[1] != pool.target or message[0] == "start":
                    return message
                pool.seen += 1
                if pool.seen == 2:
                    return ("error", pool.target, "kaputt")
                if pool.seen < 2:
                    return message

        with mock.patch.object(investigate._Readers, "__init__", init), \
                mock.patch.object(investigate._Readers, "next", next_message):
            helped, report, _ = self.run_import("helped", 2)
        self.assertEqual([item["error"] for item in report["failed"]], ["kaputt"])
        self.assertEqual(_content(helped), _content(alone))
        with helped.connect() as db:
            dangling = db.execute(
                "SELECT COUNT(*) FROM occurrences o WHERE NOT EXISTS (SELECT 1 FROM entities n WHERE n.id = o.entity_id)"
            ).fetchone()[0]
        self.assertEqual(dangling, 0)

    def test_a_helper_killed_midway_does_not_stall_the_import(self):
        alone, _, _ = self.run_import("alone", 0)
        real_next = investigate._Readers.next

        def next_message(pool, timeout=0.5):
            message = real_next(pool, timeout)
            pool.seen = getattr(pool, "seen", 0) + 1
            if pool.seen == 30:
                pool.processes[0].kill()
            return message

        result = {}

        def run():
            with mock.patch.object(investigate._Readers, "next", next_message):
                result["value"] = self.run_import("helped", 2)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(180)
        self.assertFalse(worker.is_alive(), "the import stalled")
        helped, report, _ = result["value"]
        self.assertIn("fallback", report["readers"])
        self.assertEqual(report["failed"], [])
        self.assertEqual(_content(helped), _content(alone))

    def test_helpers_that_cannot_start_leave_the_import_to_this_process(self):
        alone, _, _ = self.run_import("alone", 0)
        with mock.patch.object(investigate, "_Readers", side_effect=OSError("keine Prozesse")):
            helped, report, _ = self.run_import("helped", 2)
        self.assertEqual(report["readers"], {"count": 0, "fallback": "keine Prozesse"})
        self.assertEqual(_content(helped), _content(alone))

    def test_cancelling_leaves_only_complete_files(self):
        calls = []

        def cancelled():
            calls.append(1)
            return len(calls) > 6

        inv, report, _ = self.run_import("helped", 2, cancelled=cancelled)
        self.assertTrue(report.get("cancelled"))
        with inv.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sources WHERE state != 'ready'").fetchone()[0], 0)
            orphans = db.execute(
                "SELECT COUNT(*) FROM entities WHERE NOT EXISTS (SELECT 1 FROM occurrences o WHERE o.entity_id = entities.id)"
            ).fetchone()[0]
            self.assertEqual(orphans, 0)
            events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            sources = db.execute("SELECT COALESCE(SUM(events), 0) FROM sources").fetchone()[0]
            self.assertEqual(events, sources)
            self.assertEqual(*_text_index(db))


class ApiTest(unittest.TestCase):
    """The routes of the Untersuchen tab, as the browser calls them."""

    def setUp(self):
        from logmasque import server

        self.server = server
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.logs = S.write_samples(self.root / "logs")
        self.state = server.AppState()
        self.state.store_path = str(self.root / "store" / "zuordnung.lmstore")
        self.api = server.Api(self.state)

    def tearDown(self):
        self.tmp.cleanup()

    def wait(self, answer):
        job = self.state.jobs.get(answer["job"])
        deadline = time.monotonic() + 120
        while job.status == "running" and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(job.status, "done", job.error)
        return job.result

    def test_create_import_search_and_export(self):
        with self.assertRaises(investigate.InvestigationError):
            self.api.inv_overview({})
        created = self.api.inv_create({"name": "Fall API"})
        listed = self.api.inv_list({})
        self.assertEqual(listed["current"], created["id"])
        self.assertEqual(Path(listed["folder"]), self.root / "store" / "investigations")
        scan = self.wait(self.api.inv_scan({"paths": [str(self.root / "logs")]}))["scan"]
        self.assertEqual(len(scan["files"]), len(S.SAMPLES))
        result = self.wait(self.api.inv_import({
            "priority": [str(self.logs[IMAP])], "background": [str(self.root / "logs")],
        }))
        self.assertEqual(len(result["report"]["imported"]), len(S.SAMPLES))
        self.assertEqual(len(result["overview"]["sources"]), len(S.SAMPLES))
        self.assertIsNone(self.api.inv_overview({})["importJob"])
        with self.assertRaises(ValueError):
            self.api.inv_import({"paths": []})

        alpha = self.api.inv_suggest({"query": "alpha@"})["items"][0]
        self.assertEqual(alpha["value"], S.ALPHA)
        found = self.api.inv_search({"query": "", "entities": [alpha["id"]], "minSeverity": 0, "limit": 5})
        self.assertEqual(found["mode"], "trace")
        self.assertEqual(len(found["rows"]), 5)
        event = self.api.inv_event({"id": found["rows"][0]["id"], "anchors": [alpha["id"]]})
        self.assertTrue(event["contextLines"])
        self.assertTrue(self.api.inv_context({"id": found["rows"][0]["id"]})["rows"])
        self.assertEqual(self.api.inv_entity({"id": alpha["id"]})["value"], S.ALPHA)
        self.assertTrue(self.api.inv_graph({"id": alpha["id"], "kinds": ["ipv4"]})["nodes"])
        client = self.api.inv_suggest({"query": S.CLIENT_IP})["items"][0]["id"]
        self.assertEqual(self.api.inv_link({"a": alpha["id"], "b": client}), {"ok": True})
        self.api.inv_link({"a": alpha["id"], "b": client, "undo": True})
        self.assertTrue(self.api.inv_flag({"id": client, "action": "exclude"})["excluded"])
        self.api.inv_flag({"id": client, "action": "reset"})

        ids = self.api.inv_search({"query": S.ALPHA, "idsOnly": True, "minSeverity": 0})["ids"]
        preview = self.api.inv_export({"events": ids})
        self.assertFalse(preview["blocked"], preview["leaks"])
        self.assertNotIn(S.ALPHA, preview["text"])
        self.assertFalse(Path(self.state.store_path).exists(), "the preview wrote the store")
        if self.server.store_needs_password(None):
            with self.assertRaises(self.server.StoreError):
                self.api.inv_export({"events": ids, "confirm": True, "reviewed": True})
            self.state.store_password = "nur-ein-testkennwort"
        if preview["needsReview"]:
            with self.assertRaises(ValueError):
                self.api.inv_export({"events": ids, "confirm": True})
        released = self.api.inv_export({"events": ids, "confirm": True, "reviewed": True})
        self.assertEqual(released["text"], preview["text"])
        self.assertTrue(released["reversible"])
        stored = self.server.load_mapping(self.state.store_path, self.state.store_password)
        self.assertIn(S.ALPHA.casefold(), {original.casefold() for _, original, _ in stored.rows()})

    def test_time_and_removal_wait_for_a_running_import(self):
        created = self.api.inv_create({"name": "Warten"})
        gate = threading.Event()
        report = {"imported": [], "duplicates": [], "continued": [], "replaced": [], "failed": []}

        def slow_import(investigation, *args, **kwargs):
            gate.wait(30)
            return report

        with mock.patch.object(investigate.Investigation, "import_plan", slow_import):
            answer = self.api.inv_import({"paths": [str(self.logs[IMAP])]})
            try:
                self.assertEqual(self.api.inv_overview({})["importJob"], answer["job"])
                with self.assertRaises(investigate.InvestigationError):
                    self.api.inv_time({"mode": "fixed", "offset": 60})
                with self.assertRaises(investigate.InvestigationError):
                    self.api.inv_delete({"id": created["id"]})
            finally:
                gate.set()
            self.wait(answer)
        overview = self.wait(self.api.inv_time({"mode": "fixed", "offset": 60}))["overview"]
        self.assertEqual(overview["defaultTz"], "fixed:60")
        with self.assertRaises(investigate.InvestigationError):
            self.api.inv_time({"mode": "morgen"})
        self.assertEqual(self.api.inv_delete({"id": created["id"]})["items"], [])
        with self.assertRaises(investigate.InvestigationError):
            self.api.inv_overview({})

    def test_an_investigation_is_opened_by_its_id_only(self):
        created = self.api.inv_create({"name": "Offen"})
        self.state.investigation = None
        self.assertEqual(self.api.inv_open({"id": created["id"]})["id"], created["id"])
        for wrong in ("", "../zuordnung", "gibt-es-nicht"):
            with self.assertRaises(investigate.InvestigationError):
                self.api.inv_open({"id": wrong})

    def test_every_route_is_served(self):
        for route, name in self.server.ROUTES.items():
            if route.startswith("/api/inv/"):
                self.assertTrue(callable(getattr(self.api, name)), route)


if __name__ == "__main__":
    unittest.main()
