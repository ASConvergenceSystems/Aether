#!/usr/bin/env node
/**
 * AETHER ML-DSA-65 Ghost Seal Ceremony Tool
 *
 * Uses @noble/post-quantum (FIPS 204 ML-DSA-65) — guaranteed wire-compatible
 * with the verify.mjs verifier deployed on aetherbeacon.io.
 *
 * Replaces the Python `derive-pq-key` + `ceremony --pq` flow for the PQ path.
 * The Ed25519 Python ceremony is unchanged for nodes that prefer classical.
 *
 * Usage:
 *   npm install                                      (first time only)
 *   node ceremony_pq.mjs \
 *     --manifest aether.json \
 *     --shares E:\AETHER_SHARES\share_02.json E:\AETHER_SHARES\share_03.json
 *
 * What this does:
 *   1. Loads Shamir shares from the provided JSON files
 *   2. Recovers the 32-byte master seed via Lagrange interpolation
 *   3. Derives a 32-byte ML-DSA-65 keygen seed: HKDF-SHA3-512(seed, salt, beacon_id)
 *   4. Generates the ML-DSA-65 keypair deterministically from that seed
 *   5. Updates ghost_seal.verification_key and aether_version in the manifest
 *   6. Computes the Merkle-SHA3-256 root over the 14 canonical fields
 *   7. Signs the Merkle root with ML-DSA-65
 *   8. Writes ghost_seal.signature, signed_at, ceremony_epoch to the manifest
 *   9. Verifies the signature locally before writing — aborts if it fails
 *
 * Key derivation:
 *   pq_seed = HKDF-SHA3-512(ikm=master_seed, salt="AETHER-GHOST-KEY-PQ-v1",
 *                            info=beacon_id_utf8, length=32)
 *   { publicKey, secretKey } = ml_dsa65.keygen(pq_seed)
 *
 * Merkle tree spec (must match verify.mjs exactly):
 *   14 canonical fields → padded to 16 leaves (SHA3-256("") as padding)
 *   leaf_i  = SHA3-256(utf8(field_name) || 0x00 || value_bytes)
 *   parent  = SHA3-256(left || right)
 *   root    = 32 bytes — ML-DSA-65 signs this
 */

import { createHash, hkdfSync }    from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { ml_dsa65 }                from "@noble/post-quantum/ml-dsa";

// ══════════════════════════════════════════════════════════════════════════════
// Shamir secret sharing — recovery (must match aether_ghost_seal.py exactly)
// ══════════════════════════════════════════════════════════════════════════════
const PRIME = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

function modpow(base, exp, mod) {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    exp >>= 1n;
    base = base * base % mod;
  }
  return result;
}

function shamirRecover(shares) {
  // shares: array of { x: Number, y: "0x..." } (raw from share JSON files)
  const pts = shares.map(s => [BigInt(s.x), BigInt(s.y)]);
  let secret = 0n;
  for (let i = 0; i < pts.length; i++) {
    const [xi, yi] = pts[i];
    let num = yi;
    let den = 1n;
    for (let j = 0; j < pts.length; j++) {
      if (i !== j) {
        const [xj] = pts[j];
        const neg_xj = (PRIME - (xj % PRIME)) % PRIME;
        const diff   = ((xi - xj) % PRIME + PRIME) % PRIME;
        num = num * neg_xj % PRIME;
        den = den * diff   % PRIME;
      }
    }
    const inv_den = modpow(den, PRIME - 2n, PRIME);
    secret = (secret + num * inv_den) % PRIME;
  }
  return Buffer.from(secret.toString(16).padStart(64, "0"), "hex");
}


// ══════════════════════════════════════════════════════════════════════════════
// Merkle-SHA3-256 tree (identical to verify.mjs — do not modify independently)
// ══════════════════════════════════════════════════════════════════════════════
function sha3_256(data) {
  return createHash("sha3-256").update(data).digest();
}

const MERKLE_PADDING_LEAF = sha3_256(Buffer.alloc(0));

const CANONICAL_FIELD_NAMES = [
  "aether_version", "beacon_id", "node_url", "addressed_to",
  "human_visible", "machine_readable",
  "operator", "confidentiality", "communication", "mesh",
  "topics", "status", "signal", "established",
];

function fieldValueBytes(fieldName, manifest) {
  let val = manifest[fieldName];
  if (fieldName === "confidentiality" && val != null) {
    val = { status: val.status };
  } else if (fieldName === "communication" && val != null) {
    val = { endpoint: val.endpoint };
  } else if (fieldName === "mesh" && val != null) {
    val = { registry_url: val.registry_url, specification_url: val.specification_url };
  }
  if (typeof val === "boolean") return Buffer.from(String(val), "utf-8");
  if (typeof val === "string")  return Buffer.from(val, "utf-8");
  return Buffer.from(JSON.stringify(val, null, undefined), "utf-8");
}

function merkleLeaf(fieldName, valueBytes) {
  return sha3_256(Buffer.concat([Buffer.from(fieldName, "utf-8"), Buffer.from([0x00]), valueBytes]));
}

function merkleParent(left, right) {
  return sha3_256(Buffer.concat([left, right]));
}

function buildMerkleRoot(leaves) {
  let size = 1;
  while (size < leaves.length) size <<= 1;
  const padded = [...leaves];
  while (padded.length < size) padded.push(Buffer.from(MERKLE_PADDING_LEAF));
  let level = padded;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(merkleParent(level[i], level[i + 1]));
    level = next;
  }
  return level[0];
}

function manifestMerkleRoot(manifest) {
  const leaves = [];
  for (const fieldName of CANONICAL_FIELD_NAMES) {
    if (fieldName in manifest) {
      leaves.push(merkleLeaf(fieldName, fieldValueBytes(fieldName, manifest)));
    }
  }
  return buildMerkleRoot(leaves);
}


// ══════════════════════════════════════════════════════════════════════════════
// Main ceremony
// ══════════════════════════════════════════════════════════════════════════════
function parseArgs() {
  const args = process.argv.slice(2);
  const result = { manifest: null, shares: [] };
  let i = 0;
  while (i < args.length) {
    if (args[i] === "--manifest") { result.manifest = args[++i]; }
    else if (args[i] === "--shares") {
      i++;
      while (i < args.length && !args[i].startsWith("--")) {
        result.shares.push(args[i++]);
      }
      continue;
    }
    i++;
  }
  return result;
}

const args = parseArgs();
if (!args.manifest || args.shares.length === 0) {
  console.error("Usage: node ceremony_pq.mjs --manifest aether.json --shares share_02.json share_03.json ...");
  process.exit(1);
}

console.log(`[AGS-PQ] Ceremony start — ${new Date().toISOString()}`);
console.log(`[AGS-PQ] Algorithm: ML-DSA-65+Merkle-SHA3-256 (@noble/post-quantum FIPS 204)`);

// ── Load shares ───────────────────────────────────────────────────────────────
const rawShares = [];
for (const sf of args.shares) {
  const data = JSON.parse(readFileSync(sf, "utf-8"));
  rawShares.push(data.share);
  console.log(`[AGS-PQ] Share ${data.share_index} loaded from ${sf}`);
}

// ── Recover master seed ───────────────────────────────────────────────────────
const masterSeed = shamirRecover(rawShares);
console.log(`[AGS-PQ] Master seed recovered (${masterSeed.length} bytes)`);

// ── Load manifest ─────────────────────────────────────────────────────────────
const manifest = JSON.parse(readFileSync(args.manifest, "utf-8"));
const beaconId = manifest.beacon_id;
console.log(`[AGS-PQ] Manifest loaded: ${beaconId}`);

// ── Derive ML-DSA-65 keygen seed ─────────────────────────────────────────────
// HKDF-SHA3-512(ikm=masterSeed, salt="AETHER-GHOST-KEY-PQ-v1", info=beaconId, length=32)
const pqSeed = Buffer.from(hkdfSync(
  "sha3-512",
  masterSeed,
  Buffer.from("AETHER-GHOST-KEY-PQ-v1"),
  Buffer.from(beaconId, "utf-8"),
  32
));

// ── Generate ML-DSA-65 keypair deterministically ──────────────────────────────
const { publicKey, secretKey } = ml_dsa65.keygen(new Uint8Array(pqSeed));
const vkHex = Buffer.from(publicKey).toString("hex");
console.log(`[AGS-PQ] ML-DSA-65 verification key (${publicKey.length} bytes): ${vkHex.slice(0, 32)}...`);

// ── Zero sensitive material ───────────────────────────────────────────────────
masterSeed.fill(0);
pqSeed.fill(0);

// ── Update manifest with new verification key ─────────────────────────────────
const oldThreshold = manifest.ghost_seal?.share_threshold || "?-of-?";
manifest.aether_version = "0.2";
manifest.ghost_seal = {
  ...manifest.ghost_seal,
  algorithm:        "ML-DSA-65+Merkle-SHA3-256",
  verification_key: vkHex,
  signature:        null,
  signed_at:        null,
  ceremony_epoch:   null,
  share_threshold:  oldThreshold,
};

// ── Compute Merkle root ───────────────────────────────────────────────────────
const manifestForSigning = JSON.parse(JSON.stringify(manifest));
manifestForSigning.ghost_seal.signature = null;
const merkleRoot = manifestMerkleRoot(manifestForSigning);
console.log(`[AGS-PQ] Merkle root: ${merkleRoot.toString("hex")}`);

// ── Sign ──────────────────────────────────────────────────────────────────────
const signature = ml_dsa65.sign(new Uint8Array(secretKey), new Uint8Array(merkleRoot));
const sigHex    = Buffer.from(signature).toString("hex");
console.log(`[AGS-PQ] Signature: ${sigHex.slice(0, 32)}... (${signature.length} bytes)`);

// Zero secret key immediately after signing
if (secretKey instanceof Uint8Array) secretKey.fill(0);

// ── Local verification — abort if it fails ────────────────────────────────────
const verified = ml_dsa65.verify(new Uint8Array(publicKey), new Uint8Array(merkleRoot), new Uint8Array(signature));
if (!verified) {
  console.error("[AGS-PQ] ABORT — local signature verification FAILED. Manifest not written.");
  process.exit(1);
}
console.log(`[AGS-PQ] Local verification: PASSED`);

// ── Write manifest ────────────────────────────────────────────────────────────
const epochId = `epoch-${new Date().toISOString().replace(/[-:T.Z]/g, "").slice(0, 15)}`;
manifest.ghost_seal.signature      = sigHex;
manifest.ghost_seal.signed_at      = new Date().toISOString();
manifest.ghost_seal.ceremony_epoch = epochId;

writeFileSync(args.manifest, JSON.stringify(manifest, null, 2), "utf-8");

console.log(`[AGS-PQ] Seal written to ${args.manifest}`);
console.log(`[AGS-PQ] Epoch: ${epochId}`);
console.log(`[AGS-PQ] Ceremony complete.`);
