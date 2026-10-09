"""Crypto and mapping store, including compatibility with existing stores.

The export in fixtures/ was produced by the .NET calls of the earlier
PowerShell anonymizer, so these tests fail the moment stores and exports made
with it can no longer be read. All values in it are synthetic.

DPAPI exists only on Windows. LegacyDpapiStores replaces the Windows call with
a stand-in that, like DPAPI, only opens data with the entropy value it was
protected with; the real call is exercised by 'store selftest' on Windows.
"""

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from logmasque import crypto
from logmasque.mapping import Mapping
from logmasque.store import (
    DPAPI_PROTECTION,
    StoreError,
    _decrypt_portable,
    _encrypt_portable,
    _read_container,
    backup_store,
    default_store_path,
    describe_store,
    export_portable,
    import_portable,
    load_mapping,
    save_mapping,
)

FIXTURES = Path(__file__).parent / "fixtures"
# The synthetic password the fixture export was made with; it must stay as is.
FIXTURE_PASSWORD = "logtools-test-passwort"


class AesVectors(unittest.TestCase):
    def test_fips197_block(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        round_keys = crypto._expand_key(key)
        cipher = crypto._encrypt_block(plain, round_keys)
        self.assertEqual(cipher.hex(), "8ea2b7ca516745bfeafc49904b496089")
        self.assertEqual(crypto._decrypt_block(cipher, round_keys), plain)

    def test_nist_cbc_vector(self):
        key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        expected = (
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
            "9cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461"
            "b2eb05e2c39be9fcda6c19078c6a9d1b"
        )
        cipher = crypto.aes_cbc_encrypt(key, iv, plain)
        self.assertEqual(cipher.hex()[: len(expected)], expected)
        self.assertEqual(crypto.aes_cbc_decrypt(key, iv, cipher), plain)

    def test_sbox(self):
        self.assertEqual([crypto._SBOX[value] for value in (0x00, 0x01, 0x53, 0xFF)], [0x63, 0x7C, 0xED, 0x16])

    def test_padding_is_validated(self):
        key, iv = bytes(32), bytes(16)
        cipher = bytearray(crypto.aes_cbc_encrypt(key, iv, b"payload"))
        cipher[-1] ^= 0xFF
        with self.assertRaises(crypto.CryptoError):
            crypto.aes_cbc_decrypt(key, iv, bytes(cipher))


class StoreCryptoConstants(unittest.TestCase):
    """The values stores are written with; none of them may change.

    A different entropy makes the local store unreadable with a bare "invalid
    data" from Windows, and a different password format or folder strands every
    export and every mapping collected so far.
    """

    def test_entropy(self):
        self.assertEqual(crypto.DPAPI_ENTROPY, b"LogMasque-Mapping-Store-v1")
        self.assertIn(b"PowerShell-Log-Anonymizer-Mapping-v2", crypto.DPAPI_LEGACY_ENTROPIES)
        self.assertEqual(crypto.LEGACY_ENTROPY_VARIABLE, "LOGMASQUE_LEGACY_DPAPI_ENTROPY")

    def test_current_value_is_tried_first(self):
        with mock.patch.dict(os.environ, {crypto.LEGACY_ENTROPY_VARIABLE: "Example-A; Example-B ;"}):
            values = crypto.dpapi_entropies()
        self.assertEqual(values[0], crypto.DPAPI_ENTROPY)
        self.assertEqual(values[-2:], (b"Example-A", b"Example-B"))

    def test_password_format(self):
        self.assertEqual(crypto.PORTABLE_PROTECTION, "PBKDF2-SHA256-AES256-CBC-HMACSHA256")
        self.assertEqual(crypto.PORTABLE_ITERATIONS, 310000)
        self.assertEqual(crypto.MIN_PASSWORD_LENGTH, 12)
        self.assertEqual(DPAPI_PROTECTION, "DPAPI-CurrentUser")

    def test_store_path(self):
        self.assertEqual(default_store_path().name, "mapping.json")
        self.assertEqual(default_store_path().parent.name, "Anonymize-Log")


class ExistingStoreCompatibility(unittest.TestCase):
    def test_reads_export_of_the_former_tool(self):
        package = _read_container(FIXTURES / "powershell-export.fixture.json")
        self.assertEqual(package["Protection"], crypto.PORTABLE_PROTECTION)
        payload = _decrypt_portable(package, FIXTURE_PASSWORD)
        self.assertEqual(json.loads(payload.decode("utf-8")), json.loads((FIXTURES / "powershell-mapping.fixture.json").read_text()))

    def test_counters_continue_after_import(self):
        data = json.loads(_decrypt_portable(_read_container(FIXTURES / "powershell-export.fixture.json"), FIXTURE_PASSWORD))
        mapping = Mapping.from_store_dict(data)
        self.assertEqual(mapping.entry_count, 9)
        self.assertEqual(mapping.counters["IPv4"], 2)
        self.assertEqual(mapping.token("IPv4", "192.0.2.99"), "[IPv4-003]")
        self.assertEqual(mapping.token("Domain", "neu.example"), "kunde003.tld")

    def test_existing_assignments_are_reused(self):
        data = json.loads(_decrypt_portable(_read_container(FIXTURES / "powershell-export.fixture.json"), FIXTURE_PASSWORD))
        mapping = Mapping.from_store_dict(data)
        self.assertEqual(mapping.token("IPv4", "203.0.113.7"), "[IPv4-001]")
        self.assertEqual(mapping.token("Domain", "kunde-gmbh.example"), "kunde001.tld")

    def test_wrong_password_is_rejected(self):
        package = _read_container(FIXTURES / "powershell-export.fixture.json")
        with self.assertRaises(StoreError):
            _decrypt_portable(package, "falschesKennwort")

    def test_portable_package_shape_is_unchanged(self):
        package = _encrypt_portable(b'{"IPv4":{}}', FIXTURE_PASSWORD)
        self.assertEqual(
            sorted(package), sorted(["Version", "Protection", "Iterations", "Salt", "IV", "Data", "HMAC"])
        )
        self.assertEqual(package["Iterations"], 310000)
        self.assertEqual(package["Protection"], "PBKDF2-SHA256-AES256-CBC-HMACSHA256")

    def test_store_dict_keeps_its_layout(self):
        mapping = Mapping()
        mapping.token("IPv4", "203.0.113.7")
        data = mapping.to_store_dict()
        self.assertEqual(data["Version"], 2)
        for name in ("IPv4", "IPv6", "Domain", "Local", "Host", "Extra"):
            self.assertIn(name, data)
        self.assertEqual(data["IPv4"], {"203.0.113.7": "[IPv4-001]"})

    def test_reads_unprotected_store(self):
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "mapping.json"
            path.write_text(json.dumps({"IPv4": {"203.0.113.7": "[IPv4-004]"}}), encoding="utf-8")
            mapping = load_mapping(path)
            self.assertEqual(mapping.maps["IPv4"], {"203.0.113.7": "[IPv4-004]"})
            self.assertEqual(mapping.counters["IPv4"], 4)

    def test_reads_utf8_bom(self):
        import tempfile

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "mapping.json"
            path.write_text(json.dumps({"Host": {"mx1": "host007"}}), encoding="utf-8-sig")
            self.assertEqual(load_mapping(path).counters["Host"], 7)


class PasswordStore(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "mapping.json"
        self.addCleanup(self.folder.cleanup)

    def test_round_trip(self):
        mapping = Mapping()
        mapping.token("Domain", "kunde.example")
        save_mapping(self.path, mapping, password=FIXTURE_PASSWORD)
        again = load_mapping(self.path, FIXTURE_PASSWORD)
        self.assertEqual(again.maps["Domain"], {"kunde.example": "kunde001.tld"})

    def test_saving_twice_keeps_a_backup(self):
        mapping = Mapping()
        mapping.token("Domain", "kunde.example")
        save_mapping(self.path, mapping, password=FIXTURE_PASSWORD)
        backup = save_mapping(self.path, mapping, password=FIXTURE_PASSWORD)
        self.assertIsNotNone(backup)
        self.assertTrue(Path(backup).is_file())

    def test_backup_keeps_the_previous_content(self):
        first = Mapping()
        first.token("Domain", "alt.example")
        save_mapping(self.path, first, password=FIXTURE_PASSWORD)
        second = Mapping()
        second.token("Domain", "neu.example")
        backup = save_mapping(self.path, second, password=FIXTURE_PASSWORD)
        restored = load_mapping(backup, FIXTURE_PASSWORD)
        self.assertEqual(restored.maps["Domain"], {"alt.example": "kunde001.tld"})

    def test_export_and_import(self):
        mapping = Mapping()
        mapping.token("IPv4", "203.0.113.7")
        save_mapping(self.path, mapping, password=FIXTURE_PASSWORD)
        portable = Path(self.folder.name) / "backup.anonstore"
        export_portable(self.path, portable, FIXTURE_PASSWORD, store_password=FIXTURE_PASSWORD)
        import_portable(portable, self.path, FIXTURE_PASSWORD, force=True, store_password=FIXTURE_PASSWORD)
        self.assertEqual(load_mapping(self.path, FIXTURE_PASSWORD).maps["IPv4"], {"203.0.113.7": "[IPv4-001]"})

    def test_short_password_is_refused(self):
        with self.assertRaises(StoreError):
            save_mapping(self.path, Mapping(), password="kurz")

    def test_unwritable_store_is_detected_before_work_starts(self):
        from logmasque.crypto import dpapi_available
        from logmasque.store import store_needs_password

        # On Windows DPAPI always protects the store; elsewhere a password is required.
        self.assertEqual(store_needs_password(None), not dpapi_available())
        self.assertFalse(store_needs_password(FIXTURE_PASSWORD))

    def test_saving_without_protection_is_refused(self):
        from logmasque.crypto import dpapi_available

        if dpapi_available():
            self.skipTest("DPAPI protects the store on Windows.")
        with self.assertRaises(StoreError):
            save_mapping(self.path, Mapping())

    def test_describe_reports_locked_store(self):
        mapping = Mapping()
        mapping.token("IPv4", "203.0.113.7")
        save_mapping(self.path, mapping, password=FIXTURE_PASSWORD)
        info = describe_store(self.path)
        self.assertTrue(info.exists)
        self.assertFalse(info.readable)
        info = describe_store(self.path, FIXTURE_PASSWORD)
        self.assertTrue(info.readable)
        self.assertEqual(info.total, 1)

    def test_self_test_leaves_the_real_store_alone(self):
        import os
        from unittest import mock

        from logmasque.cli import main
        from logmasque.crypto import dpapi_available

        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": self.folder.name, "LOCALAPPDATA": self.folder.name}):
            with mock.patch("builtins.print") as printed:
                self.assertEqual(main(["store", "selftest"]), 0)
            self.assertFalse(default_store_path().exists())
        self.assertTrue(printed.call_args[0][0].startswith("PASS:"))
        expected = DPAPI_PROTECTION if dpapi_available() else crypto.PORTABLE_PROTECTION
        self.assertIn(expected, printed.call_args[0][0])



def _fake_dpapi(function_name, payload, entropy_value=crypto.DPAPI_ENTROPY):
    """Stand-in for the Windows call: data opens only with the value it was protected with."""
    tag = b"FAKE-DPAPI" + hashlib.sha256(entropy_value).digest()
    if function_name == "CryptProtectData":
        return tag + payload
    if not payload.startswith(tag):
        raise crypto.CryptoError("CryptUnprotectData failed (Windows error 13: The data is invalid.)")
    return payload[len(tag):]


class LegacyDpapiStores(unittest.TestCase):
    """New stores get the neutral value; existing stores open and keep theirs."""

    LEGACY = b"PowerShell-Log-Anonymizer-Mapping-v2"
    CUSTOM = b"Example-Org-Mapping-v2"

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "mapping.json"
        for target in ("logmasque.crypto.dpapi_available", "logmasque.store.dpapi_available"):
            patcher = mock.patch(target, return_value=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch("logmasque.crypto._dpapi_call", side_effect=_fake_dpapi)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(crypto.LEGACY_ENTROPY_VARIABLE, None)

    def _write_store(self, entropy_value, ip="203.0.113.7"):
        """A store as an earlier tool would have left it."""
        mapping = Mapping()
        mapping.token("IPv4", ip)
        payload = json.dumps(mapping.to_store_dict()).encode("utf-8")
        container = {
            "Version": 2,
            "Protection": DPAPI_PROTECTION,
            "Updated": "2026-01-01T00:00:00",
            "Data": base64.b64encode(_fake_dpapi("CryptProtectData", payload, entropy_value)).decode("ascii"),
        }
        self.path.write_text(json.dumps(container), encoding="utf-8")

    def _entropy_on_disk(self):
        blob = base64.b64decode(_read_container(self.path)["Data"])
        for value in (crypto.DPAPI_ENTROPY, self.LEGACY, self.CUSTOM):
            if blob.startswith(b"FAKE-DPAPI" + hashlib.sha256(value).digest()):
                return value
        return None

    def test_new_store_gets_the_neutral_value(self):
        mapping = Mapping()
        mapping.token("IPv4", "203.0.113.7")
        save_mapping(self.path, mapping)
        self.assertEqual(self._entropy_on_disk(), crypto.DPAPI_ENTROPY)
        self.assertEqual(load_mapping(self.path).maps["IPv4"], {"203.0.113.7": "[IPv4-001]"})

    def test_store_of_the_earlier_anonymizer_opens_and_keeps_its_value(self):
        self._write_store(self.LEGACY)
        mapping = load_mapping(self.path)
        self.assertEqual(mapping.maps["IPv4"], {"203.0.113.7": "[IPv4-001]"})
        mapping.token("IPv4", "198.51.100.12")
        save_mapping(self.path, mapping)
        self.assertEqual(self._entropy_on_disk(), self.LEGACY)
        self.assertEqual(load_mapping(self.path).entry_count, 2)

    def test_unknown_value_is_reported_and_never_overwritten(self):
        self._write_store(self.CUSTOM)
        before = self.path.read_bytes()
        with self.assertRaises(StoreError) as raised:
            load_mapping(self.path)
        self.assertIn(crypto.LEGACY_ENTROPY_VARIABLE, str(raised.exception))
        with self.assertRaises(StoreError):
            save_mapping(self.path, Mapping())
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.glob("mapping.json.bak-*")), [])

    def test_value_from_the_environment_opens_the_store_in_place(self):
        self._write_store(self.CUSTOM)
        os.environ[crypto.LEGACY_ENTROPY_VARIABLE] = self.CUSTOM.decode()
        mapping = load_mapping(self.path)
        self.assertEqual(mapping.maps["IPv4"], {"203.0.113.7": "[IPv4-001]"})
        save_mapping(self.path, mapping)
        self.assertEqual(self._entropy_on_disk(), self.CUSTOM)

    def test_import_replaces_an_unreadable_store_and_keeps_a_backup(self):
        self._write_store(self.CUSTOM)
        original = self.path.read_bytes()
        portable = Path(self.folder.name) / "backup.anonstore"
        portable.write_text(json.dumps(_encrypt_portable(b'{"IPv4": {"192.0.2.10": "[IPv4-004]"}, "IPv6": {}, '
                                                         b'"Domain": {}, "Local": {}, "Host": {}, "Extra": {}}',
                                                         FIXTURE_PASSWORD)), encoding="utf-8")
        backup = import_portable(portable, self.path, FIXTURE_PASSWORD, force=True)
        self.assertEqual(Path(backup).read_bytes(), original)
        self.assertEqual(self._entropy_on_disk(), crypto.DPAPI_ENTROPY)
        self.assertEqual(load_mapping(self.path).maps["IPv4"], {"192.0.2.10": "[IPv4-004]"})

    def test_check_names_the_kind_of_value_not_the_value(self):
        from logmasque.store import check_store

        self._write_store(self.LEGACY)
        report = dict(check_store(self.path))
        self.assertEqual(report["DPAPI entropy"], "legacy (earlier PowerShell anonymizer)")
        self.assertNotIn(self.LEGACY.decode(), " ".join(report.values()))


if __name__ == "__main__":
    unittest.main()
