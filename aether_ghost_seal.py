#!/usr/bin/env python3
"""
AETHER Ghost Seal Protocol — Reference Implementation
Aegis Secure Convergence Systems LLC
Apache 2.0 License

Implements the full Ghost Seal ceremony per AETHER Standard §15:
  - Share generation (Shamir t-of-n)
  - Ghost Key derivation (HKDF-SHA3-512)
  - Canonical serialization / Merkle tree of aether.json
  - Ed25519 signing   (AGS v0.1/v0.2, classical)
  - ML-DSA-65 signing (AGS v0.3, post-quantum) — requires dilithium-py
  - Secure key destruction
  - X25519 encryption keypair generation (classical)
  - ML-KEM-768 encryption keypair generation (post-quantum) — requires kyber-py
  - Agent-side verification
  - TPM 2.0 hardware root of trust (Windows, --tpm flag)

Requirements (classical):
    pip install cryptography

Requirements (post-quantum, add with --pq flag):
    pip install dilithium-py kyber-py

Usage:
    # Classical Ed25519 ceremony (USB shares only)
    python aether_ghost_seal.py setup    --manifest aether.json --threshold 3 --shares 5
    python aether_ghost_seal.py ceremony --manifest aether.json --shares s1.json s2.json s3.json
    python aether_ghost_seal.py verify   --manifest aether.json

    # Post-quantum ML-DSA-65 ceremony
    python aether_ghost_seal.py setup    --manifest aether.json --threshold 3 --shares 5 --pq
    python aether_ghost_seal.py ceremony --manifest aether.json --shares s1.json s2.json s3.json --pq
    python aether_ghost_seal.py verify   --manifest aether.json   # auto-detects algorithm

    # TPM-backed ceremony (share 1 sealed to Dell TPM)
    python aether_ghost_seal.py setup    --manifest aether.json --threshold 3 --shares 5 --tpm [--pq]
    python aether_ghost_seal.py ceremony --manifest aether.json --shares s2.json s3.json --tpm [--pq]

    # Encryption keypair generation
    python aether_ghost_seal.py keygen-encryption          # X25519 (classical)
    python aether_ghost_seal.py keygen-encryption --pq     # ML-KEM-768 (post-quantum)
"""

import os
import sys
import json
import ctypes
import hashlib
import secrets
import argparse
from pathlib import Path
from datetime import datetime, timezone

# TPM support (Windows only — graceful fallback if unavailable)
try:
    from tpm_windows import tpm_random, tpm_seal, tpm_unseal, tpm_info, tpm_key_exists
    TPM_AVAILABLE = True
except Exception:
    TPM_AVAILABLE = False

TPM_KEY_NAME  = "AETHER-GHOST-SEAL-SHARE-1"
TPM_SHARE_IDX = 1  # Share index sealed to TPM

# ── Classical imports (always required) ───────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("[AGS] ERROR: pip install cryptography")

# ── Post-quantum imports (optional — loaded on demand) ────────────────────────
def _require_pq():
    """Import PQ libraries, exit with helpful message if absent."""
    global _Dilithium3, _Kyber768
    try:
        from dilithium_py.dilithium import Dilithium3 as _D3
        _Dilithium3 = _D3
    except ImportError:
        sys.exit("[AGS] ERROR: pip install dilithium-py   (required for --pq ML-DSA-65 ceremony)")
    try:
        from kyber_py.kyber import Kyber768 as _K768
        _Kyber768 = _K768
    except ImportError:
        sys.exit("[AGS] ERROR: pip install kyber-py   (required for --pq ML-KEM-768 keygen)")

_Dilithium3 = None
_Kyber768   = None


# ── Shamir Secret Sharing (pure Python 3, no external dependency) ─────────────
# Prime larger than 2^256 — secp256k1 field prime
_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def _mod_inverse(a: int, p: int) -> int:
    return pow(a, p - 2, p)

def shamir_split(secret_bytes: bytes, threshold: int, num_shares: int) -> list[tuple[int, int]]:
    """Split secret_bytes into (threshold, num_shares) Shamir shares over _PRIME."""
    secret = int.from_bytes(secret_bytes, "big")
    coeffs = [secret] + [int.from_bytes(secrets.token_bytes(32), "big") % _PRIME
                         for _ in range(threshold - 1)]
    shares = []
    for x in range(1, num_shares + 1):
        y = sum(c * pow(x, i, _PRIME) for i, c in enumerate(coeffs)) % _PRIME
        shares.append((x, y))
    return shares

def shamir_recover(shares: list[tuple[int, int]]) -> bytes:
    """Recover secret bytes from a list of (x, y) Shamir shares."""
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = yi
        den = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = num * (-xj) % _PRIME
                den = den * (xi - xj) % _PRIME
        secret = (secret + num * _mod_inverse(den, _PRIME)) % _PRIME
    return secret.to_bytes(32, "big")


# ── Constants ─────────────────────────────────────────────────────────────────
AGS_VERSION           = "1.0"
AGS_ALGORITHM_ED      = "Ed25519"
AGS_ALGORITHM_PQ      = "ML-DSA-65+Merkle-SHA3-256"
AGS_ENC_ALGORITHM     = "X25519+ChaCha20-Poly1305"
AGS_ENC_ALGORITHM_PQ  = "ML-KEM-768+ChaCha20-Poly1305"
HKDF_SALT_SIGN        = b"AETHER-GHOST-KEY-v1"
HKDF_SALT_SIGN_PQ     = b"AETHER-GHOST-KEY-PQ-v1"
MAX_CEREMONY_SEC      = 300

# Canonical field order per §15.4.3 (same for both classical and PQ paths)
CANONICAL_FIELDS = [
    "aether_version",
    "beacon_id",
    "node_url",
    "addressed_to",
    "human_visible",
    "machine_readable",
]


# ── Secure memory destruction ─────────────────────────────────────────────────
def secure_zero(data: bytearray) -> None:
    if not isinstance(data, bytearray):
        return
    length = len(data)
    ctypes.memset((ctypes.c_char * length).from_buffer(data), 0, length)


# ── HKDF-SHA3-512 ─────────────────────────────────────────────────────────────
def hkdf_sha3_512(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytearray:
    """HKDF using SHA3-512 per AGS §15.3. Returns bytearray for secure zeroing."""
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=length,
        salt=salt,
        info=info,
    )
    return bytearray(hkdf.derive(ikm))


# ══════════════════════════════════════════════════════════════════════════════
# Ed25519 — classical canonical serialization (§15.4.3)
# ══════════════════════════════════════════════════════════════════════════════
def canonical_serialize(manifest: dict) -> bytes:
    """
    Produce canonical serialization of aether.json per §15.4.3.
    Field order is fixed. ghost_seal.signature is excluded.
    Used by both Ed25519 and as field-value source for ML-DSA-65 Merkle leaves.
    """
    ordered = {}

    for field in CANONICAL_FIELDS:
        if field in manifest:
            ordered[field] = manifest[field]

    if "operator" in manifest:
        ordered["operator"] = manifest["operator"]
    if "confidentiality" in manifest:
        ordered["confidentiality"] = {"status": manifest["confidentiality"].get("status")}
    if "communication" in manifest:
        ordered["communication"] = {"endpoint": manifest["communication"].get("endpoint")}
    if "mesh" in manifest:
        ordered["mesh"] = {
            "registry_url":      manifest["mesh"].get("registry_url"),
            "specification_url": manifest["mesh"].get("specification_url"),
        }
    for field in ["topics", "status", "signal", "established"]:
        if field in manifest:
            ordered[field] = manifest[field]

    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# Merkle-SHA3-256 tree (AGS §15.6.2 — used by ML-DSA-65 path)
# ══════════════════════════════════════════════════════════════════════════════

# All 14 canonical fields in signing order
_MERKLE_FIELD_NAMES = [
    "aether_version", "beacon_id", "node_url", "addressed_to",
    "human_visible", "machine_readable",
    "operator", "confidentiality", "communication", "mesh",
    "topics", "status", "signal", "established",
]

def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

# Padding leaf = SHA3-256(b"")  — used to pad to next power of 2
_MERKLE_PADDING_LEAF: bytes = _sha3_256(b"")

def _field_value_bytes(field_name: str, manifest: dict) -> bytes:
    """
    Canonical byte representation of a field's value for Merkle leaf computation.
    Strings → raw UTF-8.  Bools → b"true" / b"false".  Objects/arrays → compact JSON UTF-8.
    Subfield filtering matches canonical_serialize() so both paths cover identical data.
    """
    val = manifest.get(field_name)

    if field_name == "confidentiality" and val is not None:
        val = {"status": val.get("status")}
    elif field_name == "communication" and val is not None:
        val = {"endpoint": val.get("endpoint")}
    elif field_name == "mesh" and val is not None:
        val = {
            "registry_url":      val.get("registry_url"),
            "specification_url": val.get("specification_url"),
        }

    if isinstance(val, bool):
        return b"true" if val else b"false"
    if isinstance(val, str):
        return val.encode("utf-8")
    # object or array → compact JSON (key insertion order preserved in Python 3.7+)
    return json.dumps(val, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _merkle_leaf(field_name: str, value_bytes: bytes) -> bytes:
    """leaf = SHA3-256( utf8(field_name) || 0x00 || value_bytes )"""
    return _sha3_256(field_name.encode("utf-8") + b"\x00" + value_bytes)

def _merkle_parent(left: bytes, right: bytes) -> bytes:
    """parent = SHA3-256( left || right )"""
    return _sha3_256(left + right)

def _build_merkle_root(leaves: list[bytes]) -> bytes:
    """Build a balanced Merkle root from leaves, padding to next power of 2."""
    size = 1
    while size < len(leaves):
        size <<= 1
    padded = list(leaves) + [_MERKLE_PADDING_LEAF] * (size - len(leaves))

    level = padded
    while len(level) > 1:
        level = [_merkle_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]

    return level[0]  # 32 bytes

def manifest_merkle_root(manifest: dict) -> bytes:
    """
    Compute Merkle root over all canonical fields present in the manifest.
    ghost_seal.signature must be nulled before calling (same as for Ed25519).
    """
    leaves = []
    for field_name in _MERKLE_FIELD_NAMES:
        if field_name in manifest:
            vb = _field_value_bytes(field_name, manifest)
            leaves.append(_merkle_leaf(field_name, vb))
    return _build_merkle_root(leaves)


# ══════════════════════════════════════════════════════════════════════════════
# Commands
# ══════════════════════════════════════════════════════════════════════════════

def cmd_setup(manifest_path: Path, threshold: int, num_shares: int,
              use_tpm: bool = False, pq: bool = False):
    """
    One-time setup: generate Ghost Key, split into shares, write verification key.
    --pq:  generate ML-DSA-65 keypair (requires dilithium-py).
           The 32-byte seed is Shamir-split; ML-DSA-65 is re-derived each ceremony.
    """
    if use_tpm and not TPM_AVAILABLE:
        sys.exit("[AGS] TPM requested but tpm_windows.py unavailable or TPM not accessible.")

    algorithm = AGS_ALGORITHM_PQ if pq else AGS_ALGORITHM_ED
    print(f"[AGS] Setup — algorithm={algorithm}, threshold={threshold}-of-{num_shares}" +
          (" [TPM HRoT active]" if use_tpm else ""))

    if pq:
        _require_pq()

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    beacon_id = manifest["beacon_id"].encode("utf-8")

    # Generate 32-byte seed (TPM entropy if available)
    seed = bytearray(tpm_random(32) if use_tpm else secrets.token_bytes(32))

    if pq:
        # Derive a 32-byte ML-DSA-65 keygen seed via HKDF-SHA3-512
        pq_seed = hkdf_sha3_512(bytes(seed), HKDF_SALT_SIGN_PQ, beacon_id, 48)
        try:
            _Dilithium3.set_drbg_seed(bytes(pq_seed))
            pk_bytes, _ = _Dilithium3.keygen()
        except (AttributeError, Warning) as e:
            secure_zero(pq_seed); secure_zero(seed)
            sys.exit(f"[AGS] Cannot seed dilithium-py DRBG: {e}\n"
                     "[AGS] Fix: pip install pycryptodome")
        finally:
            secure_zero(pq_seed)
            del pq_seed
        vk_hex = pk_bytes.hex()
        print(f"[AGS] ML-DSA-65 verification key ({len(pk_bytes)} bytes): {vk_hex[:32]}...")
    else:
        # Ed25519: derive signing key via HKDF-SHA3-512
        sk_bytes = hkdf_sha3_512(bytes(seed), HKDF_SALT_SIGN, beacon_id, 32)
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(sk_bytes))
        vk_hex = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        secure_zero(sk_bytes)
        del sk_bytes, private_key
        print(f"[AGS] Ed25519 verification key: {vk_hex}")

    # Shamir-split the master seed
    raw_shares = shamir_split(bytes(seed), threshold, num_shares)
    secure_zero(seed)
    del seed

    print(f"[AGS] Shares generated: {num_shares}")

    share_dir = manifest_path.parent / "shares"
    share_dir.mkdir(exist_ok=True)
    for i, (x, y) in enumerate(raw_shares, 1):
        share_payload = json.dumps({
            "share_index":  i,
            "beacon_id":    manifest["beacon_id"],
            "algorithm":    algorithm,
            "share":        {"x": x, "y": hex(y)},
            "threshold":    threshold,
            "total_shares": num_shares,
        }).encode("utf-8")

        if use_tpm and i == TPM_SHARE_IDX:
            ct = tpm_seal(share_payload, TPM_KEY_NAME)
            tpm_share_file = share_dir / "share_01_TPM_SEALED.bin"
            tpm_share_file.write_bytes(ct)
            print(f"[AGS] Share {i} -> TPM SEALED ({TPM_KEY_NAME}) + {tpm_share_file.name}")
        else:
            share_file = share_dir / f"share_{i:02d}.json"
            with open(share_file, "w", encoding="utf-8") as f:
                json.dump({
                    "share_index":    i,
                    "beacon_id":      manifest["beacon_id"],
                    "algorithm":      algorithm,
                    "share":          {"x": x, "y": hex(y)},
                    "threshold":      threshold,
                    "total_shares":   num_shares,
                    "WARNING":        "Keep this file secure and offline. Never store all shares together.",
                }, f, indent=2)
            print(f"[AGS] Share {i} -> {share_file}")

    manifest["ghost_seal"] = {
        "algorithm":        algorithm,
        "verification_key": vk_hex,
        "signature":        None,
        "signed_at":        None,
        "ceremony_epoch":   None,
        "share_threshold":  f"{threshold}-of-{num_shares}",
    }
    if pq:
        manifest["aether_version"] = "0.2"

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[AGS] Setup complete. Run ceremony to sign.")
    print(f"[AGS] IMPORTANT: Move share files to separate physical media now.")
    print(f"[AGS] IMPORTANT: Delete shares/ directory from this machine after distribution.")


def cmd_ceremony(manifest_path: Path, share_files: list[Path],
                 use_tpm: bool = False, pq: bool = False):
    """
    Signing ceremony: assemble Ghost Key from shares, sign manifest, destroy key.
    Algorithm is read from manifest's ghost_seal.algorithm (--pq flag auto-set if PQ).
    """
    import time
    ceremony_start = time.time()

    if use_tpm and not TPM_AVAILABLE:
        sys.exit("[AGS] TPM requested but unavailable.")

    print(f"[AGS] Ceremony start — {datetime.now(timezone.utc).isoformat()}")

    raw_shares = []

    if use_tpm:
        tpm_share_file = manifest_path.parent / "shares" / "share_01_TPM_SEALED.bin"
        if not tpm_share_file.exists():
            sys.exit(f"[AGS] TPM share file not found: {tpm_share_file}")
        payload = tpm_unseal(tpm_share_file.read_bytes(), TPM_KEY_NAME)
        data = json.loads(payload.decode("utf-8"))
        s = data["share"]
        raw_shares.append((s["x"], int(s["y"], 16)))
        print(f"[AGS] Share {data['share_index']} unsealed from TPM")

    print(f"[AGS] Loading {len(share_files)} file share(s)...")
    for sf in share_files:
        with open(sf, encoding="utf-8") as f:
            data = json.load(f)
        s = data["share"]
        raw_shares.append((s["x"], int(s["y"], 16)))
        print(f"[AGS] Share {data['share_index']} loaded from {sf.name}")

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    beacon_id = manifest["beacon_id"].encode("utf-8")

    # Detect algorithm from manifest (--pq flag is advisory; manifest is authoritative)
    algorithm = manifest.get("ghost_seal", {}).get("algorithm", AGS_ALGORITHM_ED)
    pq = (algorithm == AGS_ALGORITHM_PQ)

    if pq:
        _require_pq()
        print(f"[AGS] Algorithm: {AGS_ALGORITHM_PQ}")
    else:
        print(f"[AGS] Algorithm: {AGS_ALGORITHM_ED}")

    # Reconstruct master seed
    seed = bytearray(shamir_recover(raw_shares))

    if pq:
        # Re-derive ML-DSA-65 keygen seed and sign the Merkle root
        pq_seed = hkdf_sha3_512(bytes(seed), HKDF_SALT_SIGN_PQ, beacon_id, 48)
        try:
            _Dilithium3.set_drbg_seed(bytes(pq_seed))
            pk_bytes, sk_bytes = _Dilithium3.keygen()
        except (AttributeError, Warning) as e:
            secure_zero(pq_seed); secure_zero(seed)
            sys.exit(f"[AGS] Cannot seed dilithium-py DRBG: {e}\n"
                     "[AGS] Fix: pip install pycryptodome")
        finally:
            secure_zero(pq_seed)
            del pq_seed

        # Null signature before computing Merkle root
        manifest_copy = json.loads(json.dumps(manifest))
        if "ghost_seal" in manifest_copy:
            manifest_copy["ghost_seal"]["signature"] = None
        merkle_root = manifest_merkle_root(manifest_copy)

        # Sign the 32-byte Merkle root
        sig_bytes = _Dilithium3.sign(sk_bytes, merkle_root)
        sig_hex   = sig_bytes.hex()

        # Destroy key material
        secure_zero(seed)
        del seed, sk_bytes

        print(f"[AGS] ML-DSA-65 signature: {len(sig_bytes)} bytes")
        print(f"[AGS] Merkle root: {merkle_root.hex()}")

    else:
        # Ed25519: derive signing key, sign canonical JSON
        sk_bytes = hkdf_sha3_512(bytes(seed), HKDF_SALT_SIGN, beacon_id, 32)
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(sk_bytes))

        manifest_copy = json.loads(json.dumps(manifest))
        if "ghost_seal" in manifest_copy:
            manifest_copy["ghost_seal"]["signature"] = None
        canonical = canonical_serialize(manifest_copy)

        sig_bytes = private_key.sign(canonical)
        sig_hex   = sig_bytes.hex()

        secure_zero(seed)
        secure_zero(sk_bytes)
        del seed, sk_bytes, private_key

    ceremony_elapsed = time.time() - ceremony_start
    print(f"[AGS] Key destroyed. Ceremony duration: {ceremony_elapsed:.2f}s")

    if ceremony_elapsed > MAX_CEREMONY_SEC:
        print(f"[AGS] WARNING: Ceremony exceeded {MAX_CEREMONY_SEC}s limit.")

    epoch_id = f"epoch-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    manifest["ghost_seal"]["signature"]      = sig_hex
    manifest["ghost_seal"]["signed_at"]      = datetime.now(timezone.utc).isoformat()
    manifest["ghost_seal"]["ceremony_epoch"] = epoch_id

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[AGS] Seal written to {manifest_path}")
    print(f"[AGS] Signature: {sig_hex[:32]}...")
    print(f"[AGS] Epoch: {epoch_id}")
    print(f"[AGS] Ceremony complete.")


def cmd_verify(manifest_path: Path):
    """
    Verify the Ghost Seal on a manifest. Auto-detects Ed25519 vs ML-DSA-65.
    Can be run by anyone with the public key.
    """
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    if "ghost_seal" not in manifest:
        print("[AGS] UNSIGNED — no ghost_seal field present.")
        return

    gs = manifest["ghost_seal"]
    vk_hex    = gs.get("verification_key")
    sig_hex   = gs.get("signature")
    algorithm = gs.get("algorithm", AGS_ALGORITHM_ED)

    if not vk_hex or not sig_hex:
        print("[AGS] INVALID — ghost_seal missing verification_key or signature.")
        return

    manifest_copy = json.loads(json.dumps(manifest))
    manifest_copy["ghost_seal"]["signature"] = None

    try:
        if algorithm == AGS_ALGORITHM_PQ:
            _require_pq()
            merkle_root = manifest_merkle_root(manifest_copy)
            pk_bytes    = bytes.fromhex(vk_hex)
            sig_bytes   = bytes.fromhex(sig_hex)
            result = _Dilithium3.verify(pk_bytes, merkle_root, sig_bytes)  # bool
            if result:
                print(f"[AGS] VERIFIED — {manifest['beacon_id']} ML-DSA-65+Merkle seal is valid.")
                print(f"[AGS] Merkle root: {merkle_root.hex()}")
            else:
                print(f"[AGS] INVALID — ML-DSA-65 signature verification FAILED.")
                print(f"[AGS] Beacon should be treated as UNTRUSTED.")

        elif algorithm == AGS_ALGORITHM_ED:
            canonical  = canonical_serialize(manifest_copy)
            vk_bytes   = bytes.fromhex(vk_hex)
            sig_bytes  = bytes.fromhex(sig_hex)
            public_key = Ed25519PublicKey.from_public_bytes(vk_bytes)
            try:
                public_key.verify(sig_bytes, canonical)
                print(f"[AGS] VERIFIED — {manifest['beacon_id']} Ed25519 seal is valid.")
            except InvalidSignature:
                print(f"[AGS] INVALID — Ed25519 signature verification FAILED.")
                print(f"[AGS] Beacon should be treated as UNTRUSTED.")

        else:
            print(f"[AGS] UNSUPPORTED — unknown algorithm: {algorithm}")
            return

        print(f"[AGS] Algorithm:  {algorithm}")
        print(f"[AGS] Signed at:  {gs.get('signed_at')}")
        print(f"[AGS] Epoch:      {gs.get('ceremony_epoch')}")
        print(f"[AGS] Threshold:  {gs.get('share_threshold')}")

    except Exception as e:
        print(f"[AGS] ERROR — {e}")


def cmd_derive_pq_key(manifest_path: Path, share_files: list[Path], use_tpm: bool = False):
    """
    Upgrade an existing beacon from Ed25519 to ML-DSA-65+Merkle-SHA3-256 without
    generating new shares.

    Recovers the master seed from the existing USB/TPM shares, derives a new
    ML-DSA-65 verification key using HKDF-SHA3-512 with salt AETHER-GHOST-KEY-PQ-v1
    (distinct from the Ed25519 salt), and writes the new algorithm + verification_key
    to the manifest.  The signature is cleared — run `ceremony` immediately after.

    Usage:
        python aether_ghost_seal.py derive-pq-key \\
            --manifest aether.json \\
            --shares E:\\AETHER_SHARES\\share_02.json E:\\AETHER_SHARES\\share_03.json \\
            [--tpm]
        python aether_ghost_seal.py ceremony \\
            --manifest aether.json \\
            --shares E:\\AETHER_SHARES\\share_02.json E:\\AETHER_SHARES\\share_03.json \\
            [--tpm]
    """
    _require_pq()

    if use_tpm and not TPM_AVAILABLE:
        sys.exit("[AGS] TPM requested but unavailable.")

    print(f"[AGS] derive-pq-key: upgrading to {AGS_ALGORITHM_PQ} using existing shares")

    raw_shares = []

    if use_tpm:
        tpm_share_file = manifest_path.parent / "shares" / "share_01_TPM_SEALED.bin"
        if not tpm_share_file.exists():
            sys.exit(f"[AGS] TPM share file not found: {tpm_share_file}")
        payload = tpm_unseal(tpm_share_file.read_bytes(), TPM_KEY_NAME)
        data = json.loads(payload.decode("utf-8"))
        s = data["share"]
        raw_shares.append((s["x"], int(s["y"], 16)))
        print(f"[AGS] Share {data['share_index']} unsealed from TPM")

    print(f"[AGS] Loading {len(share_files)} file share(s)...")
    for sf in share_files:
        with open(sf, encoding="utf-8") as f:
            data = json.load(f)
        s = data["share"]
        raw_shares.append((s["x"], int(s["y"], 16)))
        print(f"[AGS] Share {data['share_index']} loaded from {sf.name}")

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    beacon_id = manifest["beacon_id"].encode("utf-8")

    # Recover master seed from existing shares
    seed = bytearray(shamir_recover(raw_shares))

    # Derive ML-DSA-65 keygen seed — DIFFERENT salt from Ed25519, same master seed
    pq_seed = hkdf_sha3_512(bytes(seed), HKDF_SALT_SIGN_PQ, beacon_id, 48)
    secure_zero(seed)
    del seed

    # Generate ML-DSA-65 keypair deterministically from the derived seed
    try:
        _Dilithium3.set_drbg_seed(bytes(pq_seed))  # dilithium-py 1.x (requires pycryptodome)
        pk_bytes, sk_bytes_tmp = _Dilithium3.keygen()
        del sk_bytes_tmp  # public key is all we need here
    except (AttributeError, Warning) as e:
        secure_zero(pq_seed)
        sys.exit(f"[AGS] Cannot seed dilithium-py DRBG: {e}\n"
                 "[AGS] Fix: pip install pycryptodome")
    finally:
        secure_zero(pq_seed)
        del pq_seed

    vk_hex = pk_bytes.hex()
    print(f"[AGS] ML-DSA-65 verification key ({len(pk_bytes)} bytes): {vk_hex[:32]}...")

    # Preserve existing share_threshold — just swap algorithm + key
    old_threshold = manifest.get("ghost_seal", {}).get("share_threshold", "?-of-?")

    manifest["ghost_seal"] = {
        "algorithm":        AGS_ALGORITHM_PQ,
        "verification_key": vk_hex,
        "signature":        None,
        "signed_at":        None,
        "ceremony_epoch":   None,
        "share_threshold":  old_threshold,
    }
    manifest["aether_version"] = "0.2"

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[AGS] Manifest updated: algorithm={AGS_ALGORITHM_PQ}, aether_version=0.2")
    print(f"[AGS] Signature cleared — run ceremony now with the same shares:")
    print(f"[AGS]   python aether_ghost_seal.py ceremony --manifest {manifest_path} "
          f"--shares <your share files> [--tpm]")


def cmd_keygen_encryption(output_dir: Path = None, pq: bool = False):
    """
    Generate an encryption keypair.
    Classical: X25519    (AGS §15.7)
    Post-quantum: ML-KEM-768  (AGS §15.7.2, --pq flag, requires kyber-py)
    """
    if pq:
        _require_pq()

        pk_bytes, sk_bytes = _Kyber768.keygen()
        pk_hex = pk_bytes.hex()
        sk_hex = sk_bytes.hex()
        alg    = AGS_ENC_ALGORITHM_PQ

        print(f"[AGS] ML-KEM-768 encryption keypair generated.")
        print(f"[AGS] Public key ({len(pk_bytes)} bytes, add to aether.json): {pk_hex[:32]}...")
        print()
        print("[AGS] Add to aether.json:")
        print(json.dumps({
            "encryption": {
                "algorithm":  alg,
                "public_key": pk_hex,
            }
        }, indent=2))
        print()
        print("[AGS] Also bump: \"aether_version\": \"0.2\"")

    else:
        private_key = X25519PrivateKey.generate()
        public_key  = private_key.public_key()

        sk_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pk_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        pk_hex = pk_bytes.hex()
        sk_hex = sk_bytes.hex()
        alg    = AGS_ENC_ALGORITHM

        print(f"[AGS] X25519 encryption keypair generated.")
        print(f"[AGS] Public key (add to aether.json): {pk_hex}")
        print()
        print("[AGS] Add to aether.json:")
        print(json.dumps({
            "encryption": {
                "algorithm":  alg,
                "public_key": pk_hex,
            }
        }, indent=2))

    sk_file = (output_dir or Path(".")) / "encryption_sk.json"
    with open(sk_file, "w", encoding="utf-8") as f:
        json.dump({
            "algorithm":   alg,
            "private_key": sk_hex,
            "WARNING":     "Keep offline. Never commit to version control.",
        }, f, indent=2)
    print(f"\n[AGS] Private key saved to {sk_file}")
    print(f"[AGS] IMPORTANT: Move to offline storage immediately.")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="AETHER Ghost Seal Protocol — Reference Implementation"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # setup
    p_setup = sub.add_parser("setup", help="One-time Ghost Key setup and share generation")
    p_setup.add_argument("--manifest",  required=True, type=Path, help="Path to aether.json")
    p_setup.add_argument("--threshold", required=True, type=int,  help="Minimum shares to reconstruct")
    p_setup.add_argument("--shares",    required=True, type=int,  help="Total shares to generate")
    p_setup.add_argument("--tpm", action="store_true", help="Seal share 1 to TPM HRoT (Windows TPM 2.0)")
    p_setup.add_argument("--pq",  action="store_true", help="Use ML-DSA-65+Merkle-SHA3-256 (post-quantum)")

    # ceremony
    p_cer = sub.add_parser("ceremony", help="Run signing ceremony")
    p_cer.add_argument("--manifest", required=True, type=Path,            help="Path to aether.json")
    p_cer.add_argument("--shares",   required=True, type=Path, nargs="+", help="USB share files")
    p_cer.add_argument("--tpm", action="store_true", help="Load share 1 from TPM HRoT")
    p_cer.add_argument("--pq",  action="store_true", help="(advisory) Confirm PQ ceremony intent; algorithm read from manifest")

    # verify
    p_ver = sub.add_parser("verify", help="Verify Ghost Seal on a manifest (auto-detects algorithm)")
    p_ver.add_argument("--manifest", required=True, type=Path, help="Path to aether.json")

    # derive-pq-key  (upgrade existing Ed25519 node to ML-DSA-65 without new shares)
    p_dpk = sub.add_parser("derive-pq-key",
                            help="Upgrade beacon to ML-DSA-65 using existing shares (no new shares needed)")
    p_dpk.add_argument("--manifest", required=True, type=Path,            help="Path to aether.json")
    p_dpk.add_argument("--shares",   required=True, type=Path, nargs="+", help="Existing USB share files")
    p_dpk.add_argument("--tpm", action="store_true", help="Also load share 1 from TPM")

    # keygen-encryption
    p_enc = sub.add_parser("keygen-encryption", help="Generate encryption keypair")
    p_enc.add_argument("--output", type=Path, default=Path("."), help="Output directory for private key")
    p_enc.add_argument("--pq",  action="store_true", help="Generate ML-KEM-768 keypair instead of X25519")

    args = parser.parse_args()

    if args.command == "setup":
        cmd_setup(args.manifest, args.threshold, args.shares,
                  use_tpm=args.tpm, pq=args.pq)
    elif args.command == "ceremony":
        cmd_ceremony(args.manifest, args.shares,
                     use_tpm=args.tpm, pq=args.pq)
    elif args.command == "verify":
        cmd_verify(args.manifest)
    elif args.command == "derive-pq-key":
        cmd_derive_pq_key(args.manifest, args.shares, use_tpm=args.tpm)
    elif args.command == "keygen-encryption":
        cmd_keygen_encryption(args.output, pq=args.pq)


if __name__ == "__main__":
    main()
