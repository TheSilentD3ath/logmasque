"""Cryptographic primitives for the mapping store and its portable export.

Two formats are read and written byte-for-byte the way the earlier PowerShell
anonymizer made them, so its stores and exports stay usable:

* the local store, protected with Windows DPAPI for the current user,
* the portable ``.anonstore`` package: PBKDF2-SHA256 -> AES-256-CBC, then
  HMAC-SHA256 over salt + IV + ciphertext.

AES is implemented here in pure Python so the tool needs nothing beyond the
standard library on a locked-down machine. It only ever runs over small mapping
files - a 179 KB store takes well under a second - and it is checked against the
NIST AES-256-CBC vectors and against an export of the earlier tool in the test suite.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys

# DPAPI ties a store to the Windows account; the entropy is an additional value
# the caller must present again to decrypt. It is not a secret and adds no
# protection against the account itself, but a store protected with one value
# cannot be opened with another. New stores get this value. Never change it.
DPAPI_ENTROPY = b"LogMasque-Mapping-Store-v1"

# Values earlier tools protected their stores with. They are tried when a store
# is opened, and a store keeps the value it was written with.
DPAPI_LEGACY_ENTROPIES = (b"PowerShell-Log-Anonymizer-Mapping-v2",)

# Builds outside this repository may have used a value of their own. It can be
# supplied here, several separated by ";", so such a store opens in place.
LEGACY_ENTROPY_VARIABLE = "LOGMASQUE_LEGACY_DPAPI_ENTROPY"
PORTABLE_PROTECTION = "PBKDF2-SHA256-AES256-CBC-HMACSHA256"
PORTABLE_ITERATIONS = 310000
MIN_PASSWORD_LENGTH = 12


class CryptoError(RuntimeError):
    """Raised when data cannot be protected or unprotected."""


# --------------------------------------------------------------------------
# GF(2^8) tables, AES state helpers
# --------------------------------------------------------------------------

def _build_tables() -> tuple[list[int], list[int], list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    value = 1
    for i in range(255):
        exp[i] = value
        log[value] = i
        value ^= ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF
    for i in range(255, 512):
        exp[i] = exp[i - 255]

    sbox = [0] * 256
    inv_sbox = [0] * 256
    for i in range(256):
        inverse = 0 if i == 0 else exp[255 - log[i]]
        result = inverse
        for _ in range(4):
            inverse = ((inverse << 1) | (inverse >> 7)) & 0xFF
            result ^= inverse
        result ^= 0x63
        sbox[i] = result
        inv_sbox[result] = i
    return exp, log, sbox, inv_sbox


_EXP, _LOG, _SBOX, _INV_SBOX = _build_tables()


def _gmul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


_MUL = {factor: [_gmul(factor, value) for value in range(256)] for factor in (2, 3, 9, 11, 13, 14)}
_RCON = [0x01]
for _ in range(13):
    _RCON.append(((_RCON[-1] << 1) ^ (0x1B if _RCON[-1] & 0x80 else 0)) & 0xFF)


def _expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 32:
        raise CryptoError("Only AES-256 keys are supported.")
    words = [list(key[i : i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = list(words[i - 1])
        if i % 8 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 8 - 1]
        elif i % 8 == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - 8][j] ^ temp[j] for j in range(4)])
    return [sum(words[4 * r : 4 * r + 4], []) for r in range(15)]


def _encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = [block[i] ^ round_keys[0][i] for i in range(16)]
    for rnd in range(1, 15):
        state = [_SBOX[b] for b in state]
        state = [state[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if rnd != 14:
            mixed = []
            for column in range(4):
                a = state[4 * column : 4 * column + 4]
                mixed.extend(
                    [
                        _MUL[2][a[0]] ^ _MUL[3][a[1]] ^ a[2] ^ a[3],
                        a[0] ^ _MUL[2][a[1]] ^ _MUL[3][a[2]] ^ a[3],
                        a[0] ^ a[1] ^ _MUL[2][a[2]] ^ _MUL[3][a[3]],
                        _MUL[3][a[0]] ^ a[1] ^ a[2] ^ _MUL[2][a[3]],
                    ]
                )
            state = mixed
        state = [state[i] ^ round_keys[rnd][i] for i in range(16)]
    return bytes(state)


def _decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    state = [block[i] ^ round_keys[14][i] for i in range(16)]
    for rnd in range(13, -1, -1):
        state = [state[(i - 4 * (i % 4)) % 16] for i in range(16)]
        state = [_INV_SBOX[b] for b in state]
        state = [state[i] ^ round_keys[rnd][i] for i in range(16)]
        if rnd != 0:
            mixed = []
            for column in range(4):
                a = state[4 * column : 4 * column + 4]
                mixed.extend(
                    [
                        _MUL[14][a[0]] ^ _MUL[11][a[1]] ^ _MUL[13][a[2]] ^ _MUL[9][a[3]],
                        _MUL[9][a[0]] ^ _MUL[14][a[1]] ^ _MUL[11][a[2]] ^ _MUL[13][a[3]],
                        _MUL[13][a[0]] ^ _MUL[9][a[1]] ^ _MUL[14][a[2]] ^ _MUL[11][a[3]],
                        _MUL[11][a[0]] ^ _MUL[13][a[1]] ^ _MUL[9][a[2]] ^ _MUL[14][a[3]],
                    ]
                )
            state = mixed
    return bytes(state)


def _pad(data: bytes) -> bytes:
    padding = 16 - (len(data) % 16)
    return data + bytes([padding]) * padding


def _unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise CryptoError("Encrypted payload has an invalid length.")
    padding = data[-1]
    if padding < 1 or padding > 16 or data[-padding:] != bytes([padding]) * padding:
        raise CryptoError("Encrypted payload has invalid padding.")
    return data[:-padding]


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC with PKCS#7 padding, matching .NET's default AES settings."""
    padded = _pad(plaintext)
    round_keys = _expand_key(key)
    out = bytearray()
    previous = iv
    for offset in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[offset : offset + 16], previous))
        previous = _encrypt_block(block, round_keys)
        out += previous
    return bytes(out)


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    round_keys = _expand_key(key)
    out = bytearray()
    previous = iv
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset : offset + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(block, round_keys), previous))
        previous = block
    return _unpad(bytes(out))


def derive_key_material(password: str, salt: bytes, iterations: int) -> bytes:
    """64 bytes: the first 32 encrypt, the last 32 authenticate."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 64)


def compute_mac(mac_key: bytes, salt: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(mac_key, salt + iv + ciphertext, hashlib.sha256).digest()


def random_bytes(count: int) -> bytes:
    return os.urandom(count)


# --------------------------------------------------------------------------
# Windows DPAPI
# --------------------------------------------------------------------------

def dpapi_available() -> bool:
    return sys.platform == "win32"


CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _dpapi_library():
    """crypt32 and kernel32 with declared signatures, built once per process."""
    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    blob = ctypes.POINTER(DataBlob)

    crypt32.CryptProtectData.argtypes = [
        blob, wintypes.LPCWSTR, blob, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, blob
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        blob, ctypes.POINTER(wintypes.LPWSTR), blob, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, blob
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return ctypes, wintypes, crypt32, kernel32, DataBlob


def _dpapi_call(function_name: str, payload: bytes, entropy_value: bytes = DPAPI_ENTROPY) -> bytes:
    ctypes, wintypes, crypt32, kernel32, DataBlob = _dpapi_library()

    # The buffers must stay referenced by a live local for the whole call:
    # a blob pointing at memory the collector already reclaimed makes Windows
    # report ERROR_INVALID_DATA instead of decrypting.
    payload_buffer = ctypes.create_string_buffer(payload, len(payload))
    entropy_buffer = ctypes.create_string_buffer(entropy_value, len(entropy_value))
    data_in = DataBlob(len(payload), ctypes.cast(payload_buffer, ctypes.POINTER(ctypes.c_char)))
    entropy = DataBlob(len(entropy_value), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_char)))
    data_out = DataBlob()
    description = wintypes.LPWSTR()

    if function_name == "CryptProtectData":
        ok = crypt32.CryptProtectData(
            ctypes.byref(data_in), None, ctypes.byref(entropy),
            None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(data_out),
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(data_in), ctypes.byref(description), ctypes.byref(entropy),
            None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(data_out),
        )
    if not ok:
        code = ctypes.get_last_error()
        raise CryptoError(f"{function_name} failed (Windows error {code}: {ctypes.FormatError(code).strip()})")
    try:
        result = ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        if data_out.pbData:
            kernel32.LocalFree(data_out.pbData)
        if description:
            kernel32.LocalFree(description)
    # Keep the inputs referenced until Windows is done with them.
    del payload_buffer, entropy_buffer
    return result


def dpapi_entropies() -> tuple[bytes, ...]:
    """Every value a store may have been protected with, the current one first."""
    custom = tuple(
        value.strip().encode("utf-8")
        for value in os.environ.get(LEGACY_ENTROPY_VARIABLE, "").split(";")
        if value.strip()
    )
    return tuple(dict.fromkeys((DPAPI_ENTROPY, *DPAPI_LEGACY_ENTROPIES, *custom)))


def describe_entropy(entropy_value: bytes) -> str:
    """Which kind of value opened a store, for diagnosis; never the value itself."""
    if entropy_value == DPAPI_ENTROPY:
        return "current (LogMasque)"
    if entropy_value in DPAPI_LEGACY_ENTROPIES:
        return "legacy (earlier PowerShell anonymizer)"
    return f"legacy (from {LEGACY_ENTROPY_VARIABLE})"


def dpapi_protect(plaintext: bytes, entropy_value: bytes = DPAPI_ENTROPY) -> bytes:
    if not dpapi_available():
        raise CryptoError("DPAPI is only available on Windows.")
    return _dpapi_call("CryptProtectData", plaintext, entropy_value)


def dpapi_unprotect_with_entropy(ciphertext: bytes) -> tuple[bytes, bytes]:
    """Open a DPAPI blob with every known value; returns the plaintext and the value that fit."""
    if not dpapi_available():
        raise CryptoError("DPAPI is only available on Windows.")
    first_error: CryptoError | None = None
    for entropy_value in dpapi_entropies():
        try:
            return _dpapi_call("CryptUnprotectData", ciphertext, entropy_value), entropy_value
        except CryptoError as error:
            if first_error is None:
                first_error = error
    raise first_error if first_error else CryptoError("CryptUnprotectData failed.")


def dpapi_unprotect(ciphertext: bytes) -> bytes:
    return dpapi_unprotect_with_entropy(ciphertext)[0]
