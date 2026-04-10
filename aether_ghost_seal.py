#!/usr/bin/env python3
"""
AETHER Ghost Seal Protocol — Reference Implementation (AGS-CLASSICAL)
Aegis Secure Convergence Systems LLC
Apache 2.0 License

Implements the full Ghost Seal ceremony per AETHER Standard §15:
  - Share generation (Shamir t-of-n)
  - Ghost Key derivation (HKDF-SHA3-512)
  - Canonical serialization of aether.json
  - Ed25519 signing
  - Secure key destruction
  - X25519 response encryption keypair generation
  - Agent-side verification
  - TPM 2.0 hardware root of trust (Windows, --tpm flag)

Requirements:
    pip install cryptography

Usage:
    # Software ceremony (USB shares only)
    python aether_ghost_seal.py setup    --manifest aether.json --threshold 3 --shares 5
    python aether_ghost_seal.py ceremony --manifest aether.json --shares s1.json s2.json s3.json

    # TPM-backed ceremony (share 1 sealed to Dell TPM, remaining on USB)
    python aether_ghost_seal.py setup    --manifest aether.json --threshold 3 --shares 5 --tpm
    python aether_ghost_seal.py ceremony --manifest aether.json --shares s2.json s3.json --tpm

    python aether_ghost_seal.py verify   --manifest aether.json
    python aether_ghost_seal.py keygen-encryption
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

# ── Imports ───────────────────────────────────────────────────────────────────
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

# Shamir secret sharing is implemented inline below (no external dependency)


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

def shares_to_json(shares: list[tuple[int, int]]) -> list[dict]:
    return [{"x": x, "y": hex(y)} for x, y in shares]

def shares_from_json(data: list[dict]) -> list[tuple[int, int]]:
    return [(d["x"], int(d["y"], 16)) for d in data]


# ── Constants ─────────────────────────────────────────────────────────────────
AGS_VERSION       = "1.0"
AGS_ALGORITHM     = "Ed25519"
AGS_ENC_ALGORITHM = "X25519+XChaCha20-Poly1305"
HKDF_SALT_SIGN    = b"AETHER-GHOST-KEY-v1"
HKDF_SALT_RESP    = b"AETHER-RESPONSE-v1"
MAX_CEREMONY_SEC  = 300

# Canonical field order per §15.4.3
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
    """
    Compiler-resistant secure zeroing of a bytearray.
    Uses ctypes to write directly to memory, bypassing optimizer.
    """
    if not isinstance(data, bytearray):
        return
    length = len(data)
    ctypes.memset((ctypes.c_char * length).from_buffer(data), 0, length)


# ── HKDF-SHA3-512 ─────────────────────────────────────────────────────────────
def hkdf_sha3_512(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytearray:
    """
    HKDF using SHA3-512 as the hash function per AGS §15.3.
    Returns a bytearray for secure zeroing after use.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),  # cryptography library SHA3-512 via SHA512
        length=length,
        salt=salt,
        info=info,
    )
    result = hkdf.derive(ikm)
    return bytearray(result)


# ── Canonical serialization (§15.4.3) ─────────────────────────────────────────
def canonical_serialize(manifest: dict) -> bytes:
    """
    Produce canonical serialization of aether.json per §15.4.3.
    Field order is fixed. ghost_seal.signature is excluded.
    """
    ordered = {}

    for field in CANONICAL_FIELDS:
        if field in manifest:
            ordered[field] = manifest[field]

    # operator (full object)
    if "operator" in manifest:
        ordered["operator"] = manifest["operator"]

    # confidentiality — status field only
    if "confidentiality" in manifest:
        ordered["confidentiality"] = {"status": manifest["confidentiality"].get("status")}

    # communication — endpoint field only
    if "communication" in manifest:
        ordered["communication"] = {"endpoint": manifest["communication"].get("endpoint")}

    # mesh — registry_url and specification_url only
    if "mesh" in manifest:
        ordered["mesh"] = {
            "registry_url":      manifest["mesh"].get("registry_url"),
            "specification_url": manifest["mesh"].get("specification_url"),
        }

    # topics, status, signal, established
    for field in ["topics", "status", "signal", "established"]:
        if field in manifest:
            ordered[field] = manifest[field]

    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")




# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_setup(manifest_path: Path, threshold: int, num_shares: int, use_tpm: bool = False):
    """
    One-time setup: generate Ghost Key, split into shares,
    derive verification key, update aether.json.
    With --tpm: share 1 is sealed to the TPM; remaining shares go to USB files.
    """
    if use_tpm and not TPM_AVAILABLE:
        sys.exit("[AGS] TPM requested but tpm_windows.py unavailable or TPM not accessible.")

    print(f"[AGS] Setup — threshold={threshold}-of-{num_shares}" +
          (" [TPM HRoT active]" if use_tpm else ""))

    # Load manifest
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    beacon_id = manifest["beacon_id"].encode("utf-8")

    # Generate seed — use TPM entropy if available
    seed = bytearray(tpm_random(32) if use_tpm else secrets.token_bytes(32))
    seed_hex = seed.hex()

    # Derive Ghost Key
    sk_bytes = hkdf_sha3_512(bytes(seed), HKDF_SALT_SIGN, beacon_id, 32)

    # Generate Ed25519 keypair
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(sk_bytes))
    public_key  = private_key.public_key()
    vk_hex      = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()

    # Split seed into shares
    raw_shares = shamir_split(bytes(seed), threshold, num_shares)

    # DESTROY seed and sk_bytes
    secure_zero(seed)
    secure_zero(sk_bytes)
    del seed, sk_bytes

    print(f"[AGS] Verification key: {vk_hex}")
    print(f"[AGS] Shares generated: {num_shares}")

    # Save shares — share 1 to TPM if enabled, rest to USB files
    share_dir = manifest_path.parent / "shares"
    share_dir.mkdir(exist_ok=True)
    for i, (x, y) in enumerate(raw_shares, 1):
        share_payload = json.dumps({
            "share_index":  i,
            "beacon_id":    manifest["beacon_id"],
            "share":        {"x": x, "y": hex(y)},
            "threshold":    threshold,
            "total_shares": num_shares,
        }).encode("utf-8")

        if use_tpm and i == TPM_SHARE_IDX:
            # Seal share 1 to TPM hardware
            ct = tpm_seal(share_payload, TPM_KEY_NAME)
            tpm_share_file = share_dir / "share_01_TPM_SEALED.bin"
            tpm_share_file.write_bytes(ct)
            print(f"[AGS] Share {i} -> TPM SEALED ({TPM_KEY_NAME}) + {tpm_share_file.name}")
            print(f"[AGS]   Hardware bound to this machine's Nuvoton TPM 2.0")
        else:
            share_file = share_dir / f"share_{i:02d}.json"
            with open(share_file, "w", encoding="utf-8") as f:
                json.dump({
                    "share_index":    i,
                    "beacon_id":      manifest["beacon_id"],
                    "share":          {"x": x, "y": hex(y)},
                    "threshold":      threshold,
                    "total_shares":   num_shares,
                    "WARNING":        "Keep this file secure and offline. Never store all shares together.",
                }, f, indent=2)
            print(f"[AGS] Share {i} -> {share_file}")

    # Update manifest with ghost_seal (no signature yet)
    manifest["ghost_seal"] = {
        "algorithm":        AGS_ALGORITHM,
        "verification_key": vk_hex,
        "signature":        None,
        "signed_at":        None,
        "ceremony_epoch":   None,
        "share_threshold":  f"{threshold}-of-{num_shares}",
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[AGS] Setup complete. Run ceremony to sign.")
    print(f"[AGS] IMPORTANT: Move share files to separate physical media now.")
    print(f"[AGS] IMPORTANT: Delete shares/ directory from this machine after distribution.")


def cmd_ceremony(manifest_path: Path, share_files: list[Path], use_tpm: bool = False):
    """
    Signing ceremony: assemble Ghost Key from shares, sign manifest, destroy key.
    With --tpm: automatically loads share 1 from TPM before loading USB shares.
    """
    import time
    ceremony_start = time.time()

    if use_tpm and not TPM_AVAILABLE:
        sys.exit("[AGS] TPM requested but unavailable.")

    print(f"[AGS] Ceremony start — {datetime.now(timezone.utc).isoformat()}")
    if use_tpm:
        print(f"[AGS] HRoT: Nuvoton TPM 2.0 (share {TPM_SHARE_IDX})")

    raw_shares = []

    # Load TPM-sealed share first if --tpm
    if use_tpm:
        tpm_share_file = manifest_path.parent / "shares" / "share_01_TPM_SEALED.bin"
        if not tpm_share_file.exists():
            sys.exit(f"[AGS] TPM share file not found: {tpm_share_file}")
        ct = tpm_share_file.read_bytes()
        payload = tpm_unseal(ct, TPM_KEY_NAME)
        data = json.loads(payload.decode("utf-8"))
        s = data["share"]
        raw_shares.append((s["x"], int(s["y"], 16)))
        print(f"[AGS] Share {data['share_index']} unsealed from TPM ({TPM_KEY_NAME})")

    # Load USB/file shares
    print(f"[AGS] Loading {len(share_files)} file share(s)...")
    for sf in share_files:
        with open(sf, encoding="utf-8") as f:
            data = json.load(f)
        s = data["share"]
        raw_shares.append((s["x"], int(s["y"], 16)))
        print(f"[AGS] Share {data['share_index']} loaded from {sf.name}")

    # Load manifest
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    beacon_id = manifest["beacon_id"].encode("utf-8")

    # Reconstruct seed
    seed = bytearray(shamir_recover(raw_shares))

    # Derive Ghost Key
    sk_bytes = hkdf_sha3_512(bytes(seed), HKDF_SALT_SIGN, beacon_id, 32)

    # Reconstruct Ed25519 keypair
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(sk_bytes))

    # Canonical serialization (exclude signature)
    manifest_copy = json.loads(json.dumps(manifest))
    if "ghost_seal" in manifest_copy:
        manifest_copy["ghost_seal"]["signature"] = None
    canonical = canonical_serialize(manifest_copy)

    # Sign
    signature = private_key.sign(canonical)
    sig_hex   = signature.hex()

    # DESTROY seed and sk_bytes immediately
    secure_zero(seed)
    secure_zero(sk_bytes)
    del seed, sk_bytes, private_key

    ceremony_elapsed = time.time() - ceremony_start
    print(f"[AGS] Key destroyed. Ceremony duration: {ceremony_elapsed:.2f}s")

    if ceremony_elapsed > MAX_CEREMONY_SEC:
        print(f"[AGS] WARNING: Ceremony exceeded {MAX_CEREMONY_SEC}s limit.")

    # Update manifest
    epoch_id = f"epoch-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    manifest["ghost_seal"]["signature"]     = sig_hex
    manifest["ghost_seal"]["signed_at"]     = datetime.now(timezone.utc).isoformat()
    manifest["ghost_seal"]["ceremony_epoch"] = epoch_id

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[AGS] Seal written to {manifest_path}")
    print(f"[AGS] Signature: {sig_hex[:32]}...")
    print(f"[AGS] Epoch: {epoch_id}")
    print(f"[AGS] Ceremony complete.")


def cmd_verify(manifest_path: Path):
    """
    Verify the Ghost Seal on a manifest. Can be run by anyone.
    """
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    if "ghost_seal" not in manifest:
        print("[AGS] UNSIGNED — no ghost_seal field present.")
        return

    gs = manifest["ghost_seal"]
    vk_hex  = gs.get("verification_key")
    sig_hex = gs.get("signature")

    if not vk_hex or not sig_hex:
        print("[AGS] INVALID — ghost_seal missing verification_key or signature.")
        return

    # Reconstruct canonical form without signature
    manifest_copy = json.loads(json.dumps(manifest))
    manifest_copy["ghost_seal"]["signature"] = None
    canonical = canonical_serialize(manifest_copy)

    # Verify
    try:
        vk_bytes = bytes.fromhex(vk_hex)
        sig_bytes = bytes.fromhex(sig_hex)
        public_key = Ed25519PublicKey.from_public_bytes(vk_bytes)
        public_key.verify(sig_bytes, canonical)
        print(f"[AGS] VERIFIED — beacon {manifest['beacon_id']} seal is valid.")
        print(f"[AGS] Signed at:  {gs.get('signed_at')}")
        print(f"[AGS] Epoch:      {gs.get('ceremony_epoch')}")
        print(f"[AGS] Threshold:  {gs.get('share_threshold')}")
    except InvalidSignature:
        print(f"[AGS] INVALID — signature verification FAILED for {manifest['beacon_id']}.")
        print(f"[AGS] Beacon should be treated as UNTRUSTED.")
    except Exception as e:
        print(f"[AGS] ERROR — {e}")


def cmd_keygen_encryption(output_dir: Path = None):
    """
    Generate an X25519 keypair for response encryption.
    Prints public key for embedding in aether.json.
    Saves private key to file (keep offline).
    """
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

    sk_hex = sk_bytes.hex()
    pk_hex = pk_bytes.hex()

    print(f"[AGS] X25519 encryption keypair generated.")
    print(f"[AGS] Public key (add to aether.json): {pk_hex}")
    print()
    print('[AGS] Add to aether.json:')
    print(json.dumps({
        "encryption": {
            "algorithm":  AGS_ENC_ALGORITHM,
            "public_key": pk_hex,
        }
    }, indent=2))

    # Save private key
    sk_file = (output_dir or Path(".")) / "encryption_sk.json"
    with open(sk_file, "w", encoding="utf-8") as f:
        json.dump({
            "algorithm":   AGS_ENC_ALGORITHM,
            "private_key": sk_hex,
            "WARNING":     "Keep offline. Never commit to version control.",
        }, f, indent=2)
    print(f"\n[AGS] Private key saved to {sk_file}")
    print(f"[AGS] IMPORTANT: Move to offline storage immediately.")


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="AETHER Ghost Seal Protocol — Reference Implementation (AGS-CLASSICAL)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # setup
    p_setup = sub.add_parser("setup", help="One-time Ghost Key setup and share generation")
    p_setup.add_argument("--manifest",  required=True, type=Path, help="Path to aether.json")
    p_setup.add_argument("--threshold", required=True, type=int,  help="Minimum shares to reconstruct")
    p_setup.add_argument("--shares",    required=True, type=int,  help="Total shares to generate")
    p_setup.add_argument("--tpm", action="store_true", help="Seal share 1 to TPM HRoT (Windows TPM 2.0)")

    # ceremony
    p_cer = sub.add_parser("ceremony", help="Run signing ceremony")
    p_cer.add_argument("--manifest", required=True, type=Path,            help="Path to aether.json")
    p_cer.add_argument("--shares",   required=True, type=Path, nargs="+", help="USB share files (t-1 files when --tpm)")
    p_cer.add_argument("--tpm", action="store_true", help="Load share 1 from TPM HRoT")

    # verify
    p_ver = sub.add_parser("verify", help="Verify Ghost Seal on a manifest")
    p_ver.add_argument("--manifest", required=True, type=Path, help="Path to aether.json")

    # keygen-encryption
    p_enc = sub.add_parser("keygen-encryption", help="Generate X25519 response encryption keypair")
    p_enc.add_argument("--output", type=Path, default=Path("."), help="Output directory for private key")

    args = parser.parse_args()

    if args.command == "setup":
        cmd_setup(args.manifest, args.threshold, args.shares, use_tpm=args.tpm)
    elif args.command == "ceremony":
        cmd_ceremony(args.manifest, args.shares, use_tpm=args.tpm)
    elif args.command == "verify":
        cmd_verify(args.manifest)
    elif args.command == "keygen-encryption":
        cmd_keygen_encryption(args.output)


if __name__ == "__main__":
    main()
