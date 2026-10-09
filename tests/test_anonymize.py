"""Anonymization behaviour; token shapes must stay those of the existing store."""

import tempfile
import unittest
from pathlib import Path

from logmasque.anonymize import Anonymizer, Options, default_output_path, is_private_ipv4, normalize_ipv6
from logmasque.mapping import Mapping


def run(line, **options):
    return Anonymizer(Mapping(), Options(**options)).process_line(line)


class Replacement(unittest.TestCase):
    def test_ipv4_mail_and_domain(self):
        self.assertEqual(
            run("von bob@kunde.example via mx1.kunde.example [203.0.113.7]"),
            "von user001@kunde001.tld via host001.kunde001.tld [[IPv4-001]]",
        )

    def test_same_value_keeps_its_token(self):
        engine = Anonymizer(Mapping(), Options())
        first = engine.process_line("203.0.113.7 und 203.0.113.7")
        self.assertEqual(first, "[IPv4-001] und [IPv4-001]")

    def test_zero_padded_octets_are_not_addresses(self):
        # 000 and 007 fall outside the octet pattern, as they always did.
        self.assertEqual(run("203.000.113.007"), "203.000.113.007")

    def test_private_addresses_can_stay(self):
        self.assertEqual(run("10.0.0.5 und 203.0.113.7", keep_private_ip=True), "10.0.0.5 und [IPv4-001]")
        self.assertEqual(run("10.0.0.5", keep_private_ip=False), "[IPv4-001]")

    def test_private_ipv6_can_stay(self):
        self.assertEqual(run("::1 fe80::1 2001:db8::5", keep_private_ip=True), "::1 fe80::1 [IPv6-001]")

    def test_kept_domain_keeps_its_name_but_not_the_local_part(self):
        self.assertEqual(
            run("bob@example.com auf srv.example.com", keep_domains=("example.com",)),
            "user001@example.com auf srv.example.com",
        )

    def test_redact_mode(self):
        self.assertEqual(
            run("bob@kunde.example 203.0.113.7 srv.kunde.example", mode="redact"),
            "[MAIL-ENTFERNT] [IP-ENTFERNT] [DOMAIN-ENTFERNT]",
        )

    def test_ptr_records(self):
        self.assertEqual(run("PTR 7.113.0.203.in-addr.arpa"), "PTR [IPv4-001].in-addr.arpa")

    def test_file_extensions_are_not_domains(self):
        self.assertEqual(run("server.log tool.exe daten.csv"), "server.log tool.exe daten.csv")

    def test_multi_label_suffix(self):
        self.assertEqual(run("mail.firma.co.uk"), "host001.kunde001.tld")

    def test_hostnames_can_be_kept(self):
        self.assertEqual(run("mx1.sub.kunde.example", anonymize_hostname=False), "mx1.sub.kunde001.tld")

    def test_custom_pattern_takes_priority(self):
        self.assertEqual(run("bob@example.com", extra_patterns=(r"example\.com",)), "bob@[WERT-001]")

    def test_statistics(self):
        engine = Anonymizer(Mapping(), Options())
        engine.process_line("bob@kunde.example 203.0.113.7 mx1.kunde.example 2001:db8::1")
        self.assertEqual(engine.stats["Mail"], 1)
        self.assertEqual(engine.stats["IPv4"], 1)
        self.assertEqual(engine.stats["IPv6"], 1)
        self.assertEqual(engine.stats["Domain"], 1)

    def test_ipv6_normalization_matches_dotnet(self):
        self.assertEqual(normalize_ipv6("::FFFF:1.2.3.4"), "::ffff:1.2.3.4")
        self.assertEqual(normalize_ipv6("2001:0DB8:0000::0001"), "2001:db8::1")

    def test_private_ipv4_ranges(self):
        for address in ("10.1.2.3", "127.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "255.255.255.255"):
            self.assertTrue(is_private_ipv4(address), address)
        for address in ("203.0.113.7", "8.8.8.8", "172.32.0.1"):
            self.assertFalse(is_private_ipv4(address), address)


class Restore(unittest.TestCase):
    def test_round_trip(self):
        mapping = Mapping()
        original = "bob@kunde.example von 203.0.113.7 via mx1.kunde.example, PTR 7.113.0.203.in-addr.arpa"
        anonymized = Anonymizer(mapping, Options()).process_line(original)
        restored = Anonymizer(mapping, Options())
        self.assertEqual(restored.restore_line(anonymized), original)
        self.assertEqual(restored.unresolved, 0)

    def test_unknown_tokens_stay_untouched(self):
        engine = Anonymizer(Mapping(), Options())
        self.assertEqual(engine.restore_line("[IPv4-999] bleibt"), "[IPv4-999] bleibt")
        self.assertEqual(engine.unresolved, 1)


class Segments(unittest.TestCase):
    def test_segments_carry_original_and_category(self):
        engine = Anonymizer(Mapping(), Options())
        segments = engine.segments("von 203.0.113.7 kommt")
        categories = [segment.category for segment in segments]
        self.assertEqual(categories, [None, "IPv4", None])
        self.assertEqual(segments[1].original, "203.0.113.7")
        self.assertEqual("".join(segment.text for segment in segments), "von [IPv4-001] kommt")


class Files(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)

    def test_cp1252_file_round_trip(self):
        source = self.root / "SMTP-In-2026-08-26.log"
        source.write_text("Gruß von bob@kunde.example [203.0.113.7]\r\n", encoding="cp1252")
        target = self.root / "out.log"
        engine = Anonymizer(Mapping(), Options())
        lines = engine.process_file(source, target, encoding="auto")
        self.assertEqual(lines, 1)
        raw = target.read_bytes()
        self.assertIn("Gruß".encode("cp1252"), raw)
        self.assertIn(b"user001@kunde001.tld", raw)
        self.assertTrue(raw.endswith(b"\r\n"))

    def test_line_endings_are_preserved(self):
        source = self.root / "lf.log"
        source.write_bytes(b"eins 203.0.113.7\nzwei\n")
        target = self.root / "lf.anonym.log"
        Anonymizer(Mapping(), Options()).process_file(source, target)
        self.assertEqual(target.read_bytes().count(b"\r\n"), 0)

    def test_undecodable_bytes_survive(self):
        source = self.root / "raw.log"
        source.write_bytes(b"\x81\x8d ok 203.0.113.7\n")
        target = self.root / "raw.anonym.log"
        Anonymizer(Mapping(), Options()).process_file(source, target, encoding="ansi")
        self.assertTrue(target.read_bytes().startswith(b"\x81\x8d ok "))

    def test_default_output_name(self):
        self.assertEqual(default_output_path("/logs/a.log", None).name, "a.anonym.log")
        self.assertEqual(default_output_path("/logs/a.log", None, restore=True).name, "a.klartext.log")


if __name__ == "__main__":
    unittest.main()
