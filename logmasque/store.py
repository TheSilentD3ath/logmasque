"""Reading and writing the mapping store.

On Windows the store is one JSON container holding a DPAPI blob for the current
user, the same container the earlier PowerShell anonymizer wrote. Elsewhere the
same container is protected with the portable password format instead, and
plain (unprotected) stores are still read so nothing gets stranded.

A store is never replaced by one that cannot be read back, and a store that
cannot be opened is never overwritten by a normal save.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .crypto import (
    DPAPI_ENTROPY,
    LEGACY_ENTROPY_VARIABLE,
    MIN_PASSWORD_LENGTH,
    PORTABLE_ITERATIONS,
    PORTABLE_PROTECTION,
    CryptoError,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    compute_mac,
    derive_key_material,
    describe_entropy,
    dpapi_available,
    dpapi_protect,
    dpapi_unprotect,
    dpapi_unprotect_with_entropy,
    random_bytes,
)
from .mapping import BASE_CATEGORIES, Mapping

DPAPI_PROTECTION = "DPAPI-CurrentUser"
KEPT_BACKUPS = 5


class StoreError(RuntimeError):
    """Raised when a store cannot be read or written safely."""


class PasswordRequired(StoreError):
    """Raised when a password-protected store is opened without a password."""


def default_store_path() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or str(Path.home())
        return Path(base) / "Anonymize-Log" / "mapping.json"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "Anonymize-Log" / "mapping.json"


@dataclass
class StoreInfo:
    path: str
    exists: bool
    protection: str = ""
    updated: str = ""
    total: int = 0
    counts: dict = field(default_factory=dict)
    readable: bool = False
    message: str = ""


def _read_container(path: Path) -> dict:
    # Older stores carry a UTF-8 BOM; utf-8-sig reads both variants.
    raw = path.read_text(encoding="utf-8-sig")
    if not raw.strip():
        raise StoreError("The mapping store is empty.")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise StoreError(f"The mapping store is not valid JSON: {error}") from error


def _unwrap(container: dict, password: str | None) -> dict:
    protection = str(container.get("Protection", ""))
    if protection == DPAPI_PROTECTION:
        if not dpapi_available():
            raise StoreError(
                "This store is protected with Windows DPAPI and can only be opened on the "
                "Windows profile that created it. Export it to a .anonstore file there first."
            )
        try:
            plain = dpapi_unprotect(base64.b64decode(str(container["Data"])))
        except CryptoError as error:
            raise StoreError(
                f"The store could not be decrypted by the current Windows user with any known "
                f"entropy value: {error}. It may belong to another Windows account, or to a build "
                f"that used its own value; set {LEGACY_ENTROPY_VARIABLE} to that value, or export "
                f"the store with the tool that created it and import the .anonstore file. "
                f"The store has not been changed."
            ) from error
        return json.loads(plain.decode("utf-8"))
    if protection == PORTABLE_PROTECTION:
        if not password:
            raise PasswordRequired("This store is password protected.")
        return json.loads(_decrypt_portable(container, password).decode("utf-8"))
    if protection:
        raise StoreError(f"Unknown store protection: {protection}")
    return container


def load_mapping(path: str | Path, password: str | None = None) -> Mapping:
    path = Path(path)
    if not path.is_file():
        return Mapping()
    data = _unwrap(_read_container(path), password)
    return Mapping.from_store_dict(data)


def describe_store(path: str | Path, password: str | None = None) -> StoreInfo:
    path = Path(path)
    if not path.is_file():
        return StoreInfo(path=str(path), exists=False, message="No mapping stored yet; numbering starts at 001.")
    try:
        container = _read_container(path)
        protection = str(container.get("Protection", "")) or "Unprotected"
        data = _unwrap(container, password)
        mapping = Mapping.from_store_dict(data)
        return StoreInfo(
            path=str(path),
            exists=True,
            protection=protection,
            updated=str(container.get("Updated", "") or data.get("Updated", "")),
            total=mapping.entry_count,
            counts=mapping.counts(),
            readable=True,
        )
    except PasswordRequired as error:
        return StoreInfo(path=str(path), exists=True, protection=PORTABLE_PROTECTION, message=str(error))
    except StoreError as error:
        return StoreInfo(path=str(path), exists=True, message=str(error))


def check_store(path: str | Path, password: str | None = None) -> list[tuple[str, str]]:
    """Step-by-step diagnosis of a store, for when opening it fails.

    Reads only; it never writes, so it is safe to run against a store that
    still has to be recovered.
    """
    path = Path(path)
    report: list[tuple[str, str]] = [("Store", str(path)), ("Platform", sys.platform)]

    if dpapi_available():
        try:
            probe = b"logmasque-dpapi-probe"
            if dpapi_unprotect(dpapi_protect(probe)) == probe:
                report.append(("DPAPI round trip", "OK - this Windows account can encrypt and decrypt"))
            else:
                report.append(("DPAPI round trip", "FAILED - returned different data"))
        except CryptoError as error:
            report.append(("DPAPI round trip", f"FAILED - {error}"))
    else:
        report.append(("DPAPI", "not available, this platform uses the password format"))

    if not path.is_file():
        report.append(("File", "does not exist yet"))
        return report
    report.append(("File", f"{path.stat().st_size} bytes"))

    try:
        container = _read_container(path)
    except StoreError as error:
        report.append(("Container", f"FAILED - {error}"))
        return report
    report.append(("Container keys", ", ".join(sorted(container))))
    report.append(("Protection", str(container.get("Protection", "none"))))
    report.append(("Updated", str(container.get("Updated", "unknown"))))
    if "Data" in container:
        try:
            report.append(("Payload", f"{len(base64.b64decode(str(container['Data'])))} bytes after base64"))
        except Exception as error:
            report.append(("Payload", f"FAILED - base64 not readable: {error}"))

    try:
        data = _unwrap(container, password)
    except StoreError as error:
        report.append(("Decryption", f"FAILED - {error}"))
        return report
    mapping = Mapping.from_store_dict(data)
    report.append(("Decryption", "OK"))
    if str(container.get("Protection", "")) == DPAPI_PROTECTION:
        entropy_value = _dpapi_entropy_of(container)
        report.append(("DPAPI entropy", describe_entropy(entropy_value) if entropy_value else "unknown"))
    report.append(("Entries", f"{mapping.entry_count} ({mapping.counts()})"))
    backups = sorted(path.parent.glob(f"{path.name}.bak-*"))
    report.append(("Backups", ", ".join(item.name for item in backups) or "none"))
    return report


def store_needs_password(password: str | None = None) -> bool:
    """True when saving would fail: no DPAPI to protect the store and no password.

    Callers check this before processing anything, so a run cannot end with
    written output whose mapping could not be persisted.
    """
    return not dpapi_available() and not password


def self_test() -> str:
    """Write and read back a throwaway store with this system's protection.

    The restore preflight runs this before raw data is processed on a new
    machine. The real store is never touched. Returns the protection used.
    """
    import tempfile

    mapping = Mapping()
    mapping.token("IPv4", "192.0.2.10")
    mapping.token("Domain", "sample.example")
    password = None if dpapi_available() else "Synthetic-Selftest-Password-42!"
    expected = DPAPI_PROTECTION if password is None else PORTABLE_PROTECTION
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "mapping.json"
        save_mapping(path, mapping, password=password, backup=False)
        written = str(_read_container(path).get("Protection", ""))
        if written != expected:
            raise StoreError(f"The store was written as {written or 'unprotected'}, expected {expected}.")
        if not load_mapping(path, password).same_content(mapping):
            raise StoreError("The store read back differs from what was written.")
    return expected


def backup_store(path: str | Path) -> str | None:
    """Copy an existing store aside before it is replaced."""
    path = Path(path)
    if not path.is_file():
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, target)
    backups = sorted(path.parent.glob(f"{path.name}.bak-*"))
    for stale in backups[:-KEPT_BACKUPS]:
        stale.unlink(missing_ok=True)
    return str(target)


def _dpapi_entropy_of(container: dict) -> bytes | None:
    """The entropy value a DPAPI container opens with, or None if no known one fits."""
    try:
        return dpapi_unprotect_with_entropy(base64.b64decode(str(container["Data"])))[1]
    except (CryptoError, KeyError, ValueError):
        return None


def _entropy_to_keep(path: Path, replace_unreadable: bool) -> bytes:
    """Entropy for the next DPAPI save of path.

    A new store gets the current value. An existing one keeps the value it was
    written with, so every tool that could open it still can. A store that no
    known value opens is not overwritten unless the caller replaces it on
    purpose, as an import does.
    """
    if not path.is_file():
        return DPAPI_ENTROPY
    try:
        container = _read_container(path)
    except StoreError:
        container = None
    if container is not None and str(container.get("Protection", "")) != DPAPI_PROTECTION:
        return DPAPI_ENTROPY
    entropy_value = _dpapi_entropy_of(container) if container is not None else None
    if entropy_value is not None:
        return entropy_value
    if replace_unreadable:
        return DPAPI_ENTROPY
    raise StoreError(
        f"The existing store {path} cannot be opened by this Windows account with any known "
        f"entropy value, so it was not overwritten. See 'store check' for details."
    )


def save_mapping(
    path: str | Path,
    mapping: Mapping,
    password: str | None = None,
    backup: bool = True,
    replace_unreadable: bool = False,
) -> str | None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    use_dpapi = dpapi_available() and not password
    entropy_value = _entropy_to_keep(path, replace_unreadable) if use_dpapi else None
    backup_path = backup_store(path) if backup else None
    payload = json.dumps(mapping.to_store_dict(), indent=2).encode("utf-8")

    if use_dpapi:
        container = {
            "Version": 2,
            "Protection": DPAPI_PROTECTION,
            "Updated": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "Data": base64.b64encode(dpapi_protect(payload, entropy_value)).decode("ascii"),
        }
    elif password:
        container = _encrypt_portable(payload, password)
    else:
        raise StoreError(
            "Without Windows DPAPI the mapping store needs a password, because it can reverse "
            "the anonymization and must not be written unprotected."
        )

    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(container, indent=2), encoding="utf-8")
    _restrict_permissions(temporary)

    # Read the new file back before it replaces the old one. A store that cannot
    # be decrypted again would silently cost every mapping collected so far.
    try:
        written = Mapping.from_store_dict(_unwrap(_read_container(temporary), password))
    except Exception as error:
        temporary.unlink(missing_ok=True)
        raise StoreError(
            f"The new mapping store could not be read back and was discarded, the previous one is "
            f"untouched: {error}"
        ) from error
    if not written.same_content(mapping):
        temporary.unlink(missing_ok=True)
        raise StoreError(
            "The new mapping store did not contain what was written and was discarded; "
            "the previous one is untouched."
        )

    os.replace(temporary, path)
    return backup_path


def _restrict_permissions(path: Path) -> None:
    if sys.platform != "win32":
        os.chmod(path, 0o600)


def _encrypt_portable(payload: bytes, password: str) -> dict:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise StoreError(f"The password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    salt = random_bytes(16)
    iv = random_bytes(16)
    key_material = derive_key_material(password, salt, PORTABLE_ITERATIONS)
    ciphertext = aes_cbc_encrypt(key_material[:32], iv, payload)
    mac = compute_mac(key_material[32:], salt, iv, ciphertext)
    return {
        "Version": 1,
        "Protection": PORTABLE_PROTECTION,
        "Iterations": PORTABLE_ITERATIONS,
        "Salt": base64.b64encode(salt).decode("ascii"),
        "IV": base64.b64encode(iv).decode("ascii"),
        "Data": base64.b64encode(ciphertext).decode("ascii"),
        "HMAC": base64.b64encode(mac).decode("ascii"),
    }


def _decrypt_portable(package: dict, password: str) -> bytes:
    import hmac as _hmac

    if str(package.get("Protection")) != PORTABLE_PROTECTION:
        raise StoreError("Unknown or unencrypted export format.")
    salt = base64.b64decode(str(package["Salt"]))
    iv = base64.b64decode(str(package["IV"]))
    ciphertext = base64.b64decode(str(package["Data"]))
    expected_mac = base64.b64decode(str(package["HMAC"]))
    key_material = derive_key_material(password, salt, int(package["Iterations"]))
    actual_mac = compute_mac(key_material[32:], salt, iv, ciphertext)
    if not _hmac.compare_digest(expected_mac, actual_mac):
        raise StoreError("Incorrect password or damaged export file.")
    try:
        return aes_cbc_decrypt(key_material[:32], iv, ciphertext)
    except CryptoError as error:
        raise StoreError(f"The export file could not be decrypted: {error}") from error


def export_portable(
    store_path: str | Path,
    portable_path: str | Path,
    password: str,
    force: bool = False,
    store_password: str | None = None,
) -> None:
    """Write the local store as a password-protected .anonstore package."""
    store_path = Path(store_path)
    portable_path = Path(portable_path)
    if portable_path.exists() and not force:
        raise StoreError("The export file already exists. Confirm replacement explicitly.")
    if not store_path.is_file():
        raise StoreError(f"Local mapping store not found: {store_path}")
    mapping = load_mapping(store_path, store_password)
    if mapping.entry_count == 0:
        raise StoreError("The mapping store is empty; there is nothing to export.")
    payload = json.dumps(mapping.to_store_dict(), indent=2).encode("utf-8")
    package = _encrypt_portable(payload, password)
    portable_path.parent.mkdir(parents=True, exist_ok=True)
    portable_path.write_text(json.dumps(package, indent=2), encoding="utf-8")
    _restrict_permissions(portable_path)


def import_portable(
    portable_path: str | Path,
    store_path: str | Path,
    password: str,
    force: bool = False,
    store_password: str | None = None,
) -> str | None:
    """Replace the local store with a .anonstore package, keeping a backup."""
    portable_path = Path(portable_path)
    store_path = Path(store_path)
    package = _read_container(portable_path)
    data = json.loads(_decrypt_portable(package, password).decode("utf-8"))
    # Older backups carry only the base categories; the text categories are optional.
    missing = [name for name in BASE_CATEGORIES if name not in data]
    if missing:
        raise StoreError(f"The file is not a valid mapping store (missing: {', '.join(missing)}).")
    if store_path.is_file() and not force:
        raise StoreError("The local store already exists. Confirm replacement explicitly.")
    # An import replaces the local store on purpose, even one that cannot be opened.
    return save_mapping(store_path, Mapping.from_store_dict(data), password=store_password, replace_unreadable=True)


