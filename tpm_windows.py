"""
AETHER TPM Windows Interface
Hardware Root of Trust integration via Windows CNG (BCrypt/NCrypt).

Provides:
  tpm_random(n)          — TPM-sourced entropy via BCryptGenRandom
  tpm_seal(data, name)   — Seal bytes to TPM-backed RSA-2048 key (OAEP/SHA-256)
  tpm_unseal(ct, name)   — Unseal bytes from TPM-backed key
  tpm_info()             — TPM device info dict
  tpm_key_exists(name)   — Check if a named TPM key exists

All keys are created in the Microsoft Platform Crypto Provider (TPM 2.0).
Keys are persistent across reboots — stored in TPM NVRAM.
Only this machine's TPM can decrypt sealed data.
"""

import ctypes
import ctypes.wintypes
import subprocess
from typing import Optional

# ── BCrypt (entropy) ──────────────────────────────────────────────────────────
_bcrypt = ctypes.WinDLL("bcrypt.dll")
_bcrypt.BCryptGenRandom.restype  = ctypes.c_long   # NTSTATUS
_bcrypt.BCryptGenRandom.argtypes = [
    ctypes.c_void_p,   # hAlgorithm (NULL = system RNG)
    ctypes.c_void_p,   # pbBuffer
    ctypes.c_ulong,    # cbBuffer
    ctypes.c_ulong,    # dwFlags
]
BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002


def tpm_random(size: int) -> bytes:
    """
    Return `size` cryptographically random bytes sourced from the Windows
    system RNG, which incorporates TPM 2.0 entropy on equipped machines.
    Raises OSError on failure.
    """
    buf = (ctypes.c_ubyte * size)()
    status = _bcrypt.BCryptGenRandom(
        None, buf, ctypes.c_ulong(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG
    )
    if status != 0:
        raise OSError(f"BCryptGenRandom failed: NTSTATUS {status & 0xFFFFFFFF:#010x}")
    return bytes(buf)


# ── NCrypt (TPM key storage) ──────────────────────────────────────────────────
_ncrypt = ctypes.WinDLL("ncrypt.dll")

# Handle types (ULONG_PTR on 64-bit Windows)
NCRYPT_HANDLE     = ctypes.c_size_t
NCRYPT_PROV_HANDLE = ctypes.c_size_t
NCRYPT_KEY_HANDLE  = ctypes.c_size_t

# NCryptOpenStorageProvider
_ncrypt.NCryptOpenStorageProvider.restype  = ctypes.c_long
_ncrypt.NCryptOpenStorageProvider.argtypes = [
    ctypes.POINTER(NCRYPT_PROV_HANDLE),  # phProvider
    ctypes.c_wchar_p,                    # pszProviderName
    ctypes.c_ulong,                      # dwFlags
]

# NCryptOpenKey
_ncrypt.NCryptOpenKey.restype  = ctypes.c_long
_ncrypt.NCryptOpenKey.argtypes = [
    NCRYPT_PROV_HANDLE,                 # hProvider
    ctypes.POINTER(NCRYPT_KEY_HANDLE),  # phKey
    ctypes.c_wchar_p,                   # pszKeyName
    ctypes.c_ulong,                     # dwLegacyKeySpec
    ctypes.c_ulong,                     # dwFlags
]

# NCryptCreatePersistedKey
_ncrypt.NCryptCreatePersistedKey.restype  = ctypes.c_long
_ncrypt.NCryptCreatePersistedKey.argtypes = [
    NCRYPT_PROV_HANDLE,
    ctypes.POINTER(NCRYPT_KEY_HANDLE),
    ctypes.c_wchar_p,   # pszAlgId
    ctypes.c_wchar_p,   # pszKeyName
    ctypes.c_ulong,     # dwLegacyKeySpec
    ctypes.c_ulong,     # dwFlags
]

# NCryptSetProperty
_ncrypt.NCryptSetProperty.restype  = ctypes.c_long
_ncrypt.NCryptSetProperty.argtypes = [
    NCRYPT_HANDLE,
    ctypes.c_wchar_p,   # pszProperty
    ctypes.c_void_p,    # pbInput
    ctypes.c_ulong,     # cbInput
    ctypes.c_ulong,     # dwFlags
]

# NCryptFinalizeKey
_ncrypt.NCryptFinalizeKey.restype  = ctypes.c_long
_ncrypt.NCryptFinalizeKey.argtypes = [NCRYPT_KEY_HANDLE, ctypes.c_ulong]

# NCryptEncrypt / NCryptDecrypt
for _fn in (_ncrypt.NCryptEncrypt, _ncrypt.NCryptDecrypt):
    _fn.restype  = ctypes.c_long
    _fn.argtypes = [
        NCRYPT_KEY_HANDLE,
        ctypes.c_void_p,   # pbInput
        ctypes.c_ulong,    # cbInput
        ctypes.c_void_p,   # pPaddingInfo
        ctypes.c_void_p,   # pbOutput
        ctypes.c_ulong,    # cbOutput
        ctypes.POINTER(ctypes.c_ulong),  # pcbResult
        ctypes.c_ulong,    # dwFlags
    ]

# NCryptDeleteKey / NCryptFreeObject
_ncrypt.NCryptFreeObject.restype  = ctypes.c_long
_ncrypt.NCryptFreeObject.argtypes = [NCRYPT_HANDLE]
_ncrypt.NCryptDeleteKey.restype   = ctypes.c_long
_ncrypt.NCryptDeleteKey.argtypes  = [NCRYPT_KEY_HANDLE, ctypes.c_ulong]


# BCRYPT_OAEP_PADDING_INFO struct (for RSA-OAEP encryption)
class _OAEP(ctypes.Structure):
    _fields_ = [
        ("pszAlgId", ctypes.c_wchar_p),
        ("pbLabel",  ctypes.c_void_p),
        ("cbLabel",  ctypes.c_ulong),
    ]

_OAEP_SHA256    = _OAEP("SHA256", None, 0)
_PAD_OAEP       = 0x00000004
_MS_TPM_PROV    = "Microsoft Platform Crypto Provider"
_RSA_ALG        = "RSA"
_PROP_LENGTH    = "Length"
_KEY_LEN_2048   = ctypes.c_ulong(2048)


def _check(status: int, op: str) -> None:
    if status != 0:
        raise OSError(f"NCrypt {op} failed: {status & 0xFFFFFFFF:#010x}")


def _open_provider():
    h = NCRYPT_PROV_HANDLE(0)
    _check(_ncrypt.NCryptOpenStorageProvider(ctypes.byref(h), _MS_TPM_PROV, 0),
           "OpenStorageProvider")
    return h


def tpm_key_exists(key_name: str) -> bool:
    """Return True if a named TPM key already exists in the Platform Crypto Provider."""
    try:
        h_prov = _open_provider()
        h_key  = NCRYPT_KEY_HANDLE(0)
        status = _ncrypt.NCryptOpenKey(h_prov, ctypes.byref(h_key), key_name, 0, 0)
        if h_key.value:
            _ncrypt.NCryptFreeObject(h_key)
        _ncrypt.NCryptFreeObject(h_prov)
        return status == 0
    except Exception:
        return False


def _get_or_create_key(h_prov: NCRYPT_PROV_HANDLE, key_name: str) -> NCRYPT_KEY_HANDLE:
    """Open existing TPM key or create a new RSA-2048 one."""
    h_key = NCRYPT_KEY_HANDLE(0)
    status = _ncrypt.NCryptOpenKey(h_prov, ctypes.byref(h_key), key_name, 0, 0)
    if status == 0:
        return h_key

    # Key doesn't exist — create it
    _check(_ncrypt.NCryptCreatePersistedKey(
        h_prov, ctypes.byref(h_key), _RSA_ALG, key_name, 0, 0
    ), "CreatePersistedKey")

    _check(_ncrypt.NCryptSetProperty(
        h_key, _PROP_LENGTH,
        ctypes.byref(_KEY_LEN_2048), ctypes.sizeof(_KEY_LEN_2048), 0
    ), "SetProperty(Length)")

    _check(_ncrypt.NCryptFinalizeKey(h_key, 0), "FinalizeKey")
    return h_key


def tpm_seal(data: bytes, key_name: str = "AETHER-GHOST-SEAL-SHARE-1") -> bytes:
    """
    Encrypt `data` with a TPM 2.0 backed RSA-2048 key using OAEP/SHA-256.
    The key is created in the TPM on first use and persists in NVRAM.
    Only this machine's TPM can decrypt the result.
    """
    h_prov = _open_provider()
    h_key  = None
    try:
        h_key = _get_or_create_key(h_prov, key_name)

        cb_result = ctypes.c_ulong(0)
        # Get output buffer size
        _check(_ncrypt.NCryptEncrypt(
            h_key, data, len(data), ctypes.byref(_OAEP_SHA256),
            None, 0, ctypes.byref(cb_result), _PAD_OAEP
        ), "NCryptEncrypt(size)")

        out = (ctypes.c_ubyte * cb_result.value)()
        _check(_ncrypt.NCryptEncrypt(
            h_key, data, len(data), ctypes.byref(_OAEP_SHA256),
            out, cb_result.value, ctypes.byref(cb_result), _PAD_OAEP
        ), "NCryptEncrypt")

        return bytes(out[:cb_result.value])
    finally:
        if h_key and h_key.value:
            _ncrypt.NCryptFreeObject(h_key)
        _ncrypt.NCryptFreeObject(h_prov)


def tpm_unseal(ciphertext: bytes, key_name: str = "AETHER-GHOST-SEAL-SHARE-1") -> bytes:
    """
    Decrypt TPM-sealed data. Requires the same machine's TPM and key.
    Raises OSError if the key doesn't exist or decryption fails.
    """
    h_prov = _open_provider()
    h_key  = NCRYPT_KEY_HANDLE(0)
    try:
        _check(_ncrypt.NCryptOpenKey(h_prov, ctypes.byref(h_key), key_name, 0, 0),
               f"OpenKey({key_name})")

        cb_result = ctypes.c_ulong(0)
        _check(_ncrypt.NCryptDecrypt(
            h_key, ciphertext, len(ciphertext), ctypes.byref(_OAEP_SHA256),
            None, 0, ctypes.byref(cb_result), _PAD_OAEP
        ), "NCryptDecrypt(size)")

        out = (ctypes.c_ubyte * cb_result.value)()
        _check(_ncrypt.NCryptDecrypt(
            h_key, ciphertext, len(ciphertext), ctypes.byref(_OAEP_SHA256),
            out, cb_result.value, ctypes.byref(cb_result), _PAD_OAEP
        ), "NCryptDecrypt")

        return bytes(out[:cb_result.value])
    finally:
        if h_key.value:
            _ncrypt.NCryptFreeObject(h_key)
        _ncrypt.NCryptFreeObject(h_prov)


def tpm_info() -> dict:
    """Return TPM device information dict from tpmtool."""
    try:
        r = subprocess.run(
            ["tpmtool", "getdeviceinformation"],
            capture_output=True, text=True, timeout=10
        )
        info = {}
        for line in r.stdout.splitlines():
            line = line.strip().lstrip("-")
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
        return info
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    print("[TPM] Device info:")
    for k, v in tpm_info().items():
        print(f"  {k}: {v}")

    print("\n[TPM] Testing entropy...")
    rnd = tpm_random(32)
    print(f"  32 bytes: {rnd.hex()}")

    print("\n[TPM] Testing seal/unseal...")
    test_data = b"AETHER-TEST-PAYLOAD-0123456789ab"
    ct = tpm_seal(test_data, "AETHER-TEST-KEY")
    pt = tpm_unseal(ct, "AETHER-TEST-KEY")
    assert pt == test_data, "MISMATCH"
    print(f"  Sealed:   {ct.hex()[:32]}...")
    print(f"  Unsealed: {pt}")
    print("  TPM seal/unseal: PASS")
