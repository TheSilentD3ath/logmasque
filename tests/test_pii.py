"""Personal data in free text: names, addresses, phone numbers, companies.

Every person, company and address below is invented. The mail mirrors the shape
of a real support thread pasted as plain text: quoted headers glued to the text,
signatures run together, the sender's name repeated without any hint.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from logmasque.anonymize import Anonymizer, Options
from logmasque.mapping import Mapping

FLAT_MAIL = (
    'Bernd BeispielBernd Beispiel.04 May 10:07 AM( responded in 5 days ).From"Muster Software GmbH"'
    '<support@muster-software.example>To"Clara Probe"<c.probe@kunde.example>Sehr geehrte Frau Probe,'
    "in Ordnung. Dann warte ich noch auf Ihre Rückmeldung.Mit freundlichen Grüßen / Kind regards "
    "Bernd Beispiel | Team Lead Support DACH Muster Software GmbH | Hauptstraße 12 | D-12345 Musterstadt "
    "Tel. +49 30 1234567 | Web: https://www.muster-software.example Amtsgericht Musterstadt HRB 12345 | "
    "Geschäftsführer: Jan-Peter Probst, Anna TestHinweise zur Verarbeitung Ihrer Daten finden Sie hier."
    '---- on Wed, 29 Apr 2026 09:51:00 +0200 "Clara Probe"<c.probe@kunde.example> wrote ----'
    "Sehr geehrter Herr Beispiel, die Prozedur hat nicht geholfen. Mit freundlichen Grüßen Clara Probe "
    'Von: Muster Software GmbH (support@muster-software.example)Gesendet: Mittwoch, 22. April 2026 12:39'
    'An: "Clara Probe"Betreff: Re:[## 6221 ##] fehlende Termine (XYZ)'
)

LEAKS = (
    "Beispiel", "Bernd", "Probe", "Clara", "Probst", "Jan-Peter", "Anna Test", "Muster Software",
    "Hauptstraße", "12345 Musterstadt", "1234567", "HRB 12345", "Amtsgericht Musterstadt",
)

LOG_LINES = [
    "Mon 2026-08-26 10:15:01.123: Session 0012345678; child 1; thread 4211",
    "Mon 2026-08-26 10:15:01.145: Message size: 12345 bytes, 35578 Messages queued",
    "Mon 2026-08-26 10:15:02.001: Firewall 2 rule matched; Monitoring 2 active; Speicherplatz 50 GB frei",
    "Mon 2026-08-26 10:15:02.002: Date: Wed, 29 Apr 2026 09:51:00 +0200",
    "Mon 2026-08-26 10:15:02.003: MDaemon 26.0.1 build 12345 / ActiveSync protocol 16.1",
    "Mon 2026-08-26 10:15:02.005: Spam score 3.2 (HAM) * 1.0 RCVD_IN_DNSWL_MED, AG 1234",
    "Mon 2026-08-26 10:15:02.006: Queue ID 0049123456789 Retry 00 14 22 33 44",
]


def anonymize(text: str, mapping: Mapping | None = None, **options) -> tuple[str, Anonymizer]:
    engine = Anonymizer(mapping if mapping is not None else Mapping(), Options(**options))
    engine.learn_text(text)
    return "\n".join(engine.process_line(line) for line in text.split("\n")), engine


class FreeTextTest(unittest.TestCase):
    def test_flattened_mail_keeps_nothing_personal(self):
        output, _ = anonymize(FLAT_MAIL)
        for leak in LEAKS:
            self.assertNotIn(leak, output)
        # Text that identifies nobody stays readable.
        self.assertIn("Team Lead Support DACH", output)
        self.assertIn("[## 6221 ##]", output)

    def test_glued_names_split_at_the_capital_letter(self):
        output, engine = anonymize(FLAT_MAIL)
        token = engine.mapping.maps["Person"]["Bernd Beispiel"]
        self.assertTrue(output.startswith(token + token + ".04 May"), output[:60])

    def test_surname_shares_the_number_of_the_full_name(self):
        output, engine = anonymize(FLAT_MAIL)
        full = engine.mapping.maps["Person"]["Clara Probe"]
        surname = engine.mapping.maps["Person"]["Probe"]
        self.assertEqual(Mapping.person_number(full), Mapping.person_number(surname))
        self.assertIn(f"Sehr geehrte Frau {surname}", output)

    def test_signature_parts(self):
        output, engine = anonymize(FLAT_MAIL)
        counts = {name: count for name, count in engine.stats.items() if count}
        for category in ("Person", "Company", "Phone", "Street", "City", "Register"):
            self.assertIn(category, counts)
        self.assertIn("Tel. [TEL-001]", output)
        self.assertIn("| [STRASSE-001] | [ORT-001] Tel.", output)

    def test_closing_with_the_name_on_the_next_line(self):
        mail = "Hallo zusammen,\nanbei die Logs.\n\nViele Grüße\nDoris Dummy\nTechnik\nTel: 0641 98765-12"
        output, _ = anonymize(mail)
        self.assertNotIn("Doris", output)
        self.assertNotIn("98765", output)
        self.assertIn("Technik", output)

    def test_restore_gives_back_the_exact_text(self):
        output, engine = anonymize(FLAT_MAIL)
        restored = "\n".join(engine.restore_line(line) for line in output.split("\n"))
        self.assertEqual(restored, FLAT_MAIL)
        self.assertEqual(engine.unresolved, 0)

    def test_learned_names_carry_over_to_the_next_text(self):
        mapping = Mapping()
        anonymize(FLAT_MAIL, mapping)
        output, _ = anonymize("Rückruf an Clara Probe wegen Termin, Kopie an Beispiel.", mapping)
        self.assertNotIn("Clara Probe", output)
        self.assertNotIn("Beispiel", output)

    def test_log_lines_are_left_alone(self):
        for line in LOG_LINES:
            output, engine = anonymize(line)
            personal = {k: v for k, v in engine.stats.items() if v and k not in ("IPv4", "IPv6", "Mail", "Domain")}
            self.assertEqual(personal, {}, line)

    def test_switched_off(self):
        output, _ = anonymize(FLAT_MAIL, detect_personal=False)
        self.assertIn("Bernd Beispiel", output)

    def test_iban_needs_a_valid_checksum(self):
        output, _ = anonymize("IBAN: DE89 3704 0044 0532 0130 00, Konto alt DE89 3704 0044 0532 0130 01")
        self.assertIn("IBAN: [KONTO-001]", output)
        self.assertIn("DE89 3704 0044 0532 0130 01", output.replace("[TEL-001]", "0044 0532 0130 01"))

    def test_file_is_learned_before_it_is_written(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder, "mail.txt")
            source.write_text("Bernd Beispiel hat angerufen.\n" + FLAT_MAIL + "\n", encoding="utf-8")
            target = Path(folder, "mail.anonym.txt")
            Anonymizer(Mapping(), Options()).process_file(source, target)
            first_line = target.read_text(encoding="utf-8").splitlines()[0]
            self.assertTrue(first_line.startswith("[PERSON-"), first_line)


class OtherLanguagesTest(unittest.TestCase):
    def test_english_and_italian_mail(self):
        mail = (
            "Hello Mr. Fantasini,yes, that's correct. I recommend restarting the service after the change."
            "You can check the configuration in the log.Best regards\nTessa Fiktiv\n\n"
            "Gentile Sig.ra Inventata, grazie. Cordiali saluti\nMarco Esempio"
        )
        output, _ = anonymize(mail)
        for leak in ("Fantasini", "Tessa", "Fiktiv", "Inventata", "Marco", "Esempio"):
            self.assertNotIn(leak, output)
        self.assertIn("Hello Mr. [NAME-", output)
        self.assertIn("Gentile Sig.ra [NAME-", output)

    def test_glued_sentences_are_no_domain(self):
        output, _ = anonymize("after the change.You can check it, see mail.example.com or example.Com")
        self.assertIn("change.You can", output)
        self.assertNotIn("mail.example.com", output)


class SignatureTest(unittest.TestCase):
    def test_shared_surname_seat_and_court_glued_together(self):
        text = (
            "Mit freundlichen GrüßenTel : +49 30 1234567Geschäftsführer: Ulf und Sven Mustermann"
            "Sitz der Gesellschaft: MusterburgAmtsgericht Beispielstadt: HRB 4711UST-ID: DE123456789"
            "\nRückfrage bitte direkt an Ulf."
        )
        output, _ = anonymize(text)
        for leak in ("Ulf", "Sven", "Mustermann", "Musterburg", "Beispielstadt", "4711", "123456789"):
            self.assertNotIn(leak, output)
        self.assertIn("Geschäftsführer: [VORNAME-", output)


class OwnListsTest(unittest.TestCase):
    def test_own_term_is_plain_text_and_case_insensitive(self):
        mapping = Mapping()
        self.assertEqual(mapping.add_term("XYZ"), "[WERT-001]")
        output, _ = anonymize("Ticket (xyz) und XYZAB bleiben", mapping)
        self.assertIn("([WERT-001])", output)
        self.assertIn("XYZAB", output)

    def test_removed_term_stays_restorable(self):
        mapping = Mapping()
        mapping.add_term("XYZ")
        output, engine = anonymize("Kunde XYZ", mapping)
        mapping.remove_term("XYZ")
        self.assertEqual(anonymize("Kunde XYZ", mapping)[0], "Kunde XYZ")
        self.assertEqual(Anonymizer(mapping, Options()).restore_line(output), "Kunde XYZ")

    def test_never_replace(self):
        mapping = Mapping()
        mapping.ignore("Muster Software GmbH")
        mapping.ignore("muster-software.example")
        output, _ = anonymize(FLAT_MAIL, mapping)
        self.assertIn("Muster Software GmbH", output)
        # A kept domain covers its subdomains; the mailbox in front stays a placeholder.
        self.assertIn("https://www.muster-software.example", output)
        self.assertIn("@muster-software.example", output)
        self.assertNotIn("support@", output)
        self.assertNotIn("Clara", output)

    def test_never_replace_a_whole_address(self):
        mapping = Mapping()
        mapping.ignore("support@muster-software.example")
        output, _ = anonymize(FLAT_MAIL, mapping)
        self.assertIn("<support@muster-software.example>", output)

    def test_ignored_name_is_not_learned(self):
        mapping = Mapping()
        mapping.ignore("Bernd Beispiel")
        mapping.ignore("Beispiel")
        output, _ = anonymize(FLAT_MAIL, mapping)
        self.assertIn("Bernd Beispiel", output)
        self.assertIsNone(mapping.find("Person", "Bernd Beispiel"))

    def test_own_pattern(self):
        mapping = Mapping()
        mapping.add_pattern(r"\[## \d+ ##\]")
        output, _ = anonymize(FLAT_MAIL, mapping)
        self.assertNotIn("6221", output)


class CheckTest(unittest.TestCase):
    def test_anonymized_mail_passes_and_the_original_does_not(self):
        from logmasque.anonymize import find_leaks

        output, _ = anonymize(FLAT_MAIL)
        self.assertEqual(find_leaks(output), {})
        found = find_leaks(FLAT_MAIL)
        for label in ("Name", "Company", "Phone number", "Street", "Email address"):
            self.assertIn(label, found)

    def test_known_names_count_and_kept_values_do_not(self):
        from logmasque.anonymize import find_leaks

        mapping = Mapping()
        anonymize(FLAT_MAIL, mapping)
        mapping.ignore("Musterstadt")
        text = "Rückruf an Probe wegen der Filiale in Musterstadt."
        self.assertEqual(find_leaks(text), {})
        self.assertEqual(find_leaks(text, Mapping.from_store_dict(mapping.to_store_dict())), {"Name": 1})

    def test_secrets_are_counted_not_shown(self):
        from logmasque.anonymize import find_leaks

        found = find_leaks("password=geheim\n-----BEGIN RSA PRIVATE KEY-----")
        # The key header names a private key, so it is a secret word as well.
        self.assertEqual(found, {"Secret word": 2, "Private key": 1})

    def test_command_prints_counts_only(self):
        import io
        from contextlib import redirect_stdout

        from logmasque.cli import main

        with tempfile.TemporaryDirectory() as folder:
            original = Path(folder, "mail.txt")
            original.write_text(FLAT_MAIL, encoding="utf-8")
            printed = io.StringIO()
            with redirect_stdout(printed):
                self.assertEqual(main(["check", "--no-store", str(original)]), 2)
            for leak in LEAKS:
                self.assertNotIn(leak, printed.getvalue())
            clean = Path(folder, "mail.anonym.txt")
            clean.write_text(anonymize(FLAT_MAIL)[0], encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["check", "--no-store", str(clean)]), 0)


class StoreTest(unittest.TestCase):
    def test_lists_and_people_survive_the_store(self):
        mapping = Mapping()
        anonymize(FLAT_MAIL, mapping)
        mapping.ignore("Musterstadt")
        mapping.add_term("XYZ")
        mapping.add_pattern(r"Ticket \d+")
        reloaded = Mapping.from_store_dict(mapping.to_store_dict())
        self.assertTrue(reloaded.same_content(mapping))
        self.assertEqual(reloaded.find("Person", "CLARA PROBE"), "Clara Probe")

    def test_old_store_without_text_categories_loads(self):
        old = {"Version": 2, "IPv4": {"10.0.0.1": "[IPv4-001]"}, "IPv6": {}, "Domain": {}, "Local": {},
               "Host": {}, "Extra": {}}
        mapping = Mapping.from_store_dict(old)
        self.assertEqual(mapping.counts()["Person"], 0)
        self.assertEqual(mapping.token("IPv4", "10.0.0.2"), "[IPv4-002]")


if __name__ == "__main__":
    unittest.main()
