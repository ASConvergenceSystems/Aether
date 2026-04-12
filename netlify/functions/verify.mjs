/**
 * AETHER Beacon Verification Function
 * GET /verify?beacon_id=X  — or —  GET /verify?node_url=X
 *
 * Fetches the beacon's aether.json, reconstructs canonical form,
 * verifies the Ghost Seal, and returns a structured trust report.
 *
 * Supported algorithms:
 *   Ed25519                   — classical (AGS v0.1/v0.2, §15.6)
 *   ML-DSA-65+Merkle-SHA3-256 — post-quantum (AGS v0.3, §15.6.2)
 *
 * Merkle tree spec (ML-DSA-65 path):
 *   - 14 canonical fields (same order as classical canonical form)
 *   - Padded to 16 leaves (next power of 2) using SHA3-256(b"") padding
 *   - leaf_i  = SHA3-256(utf8(field_name) || 0x00 || value_bytes)
 *   - value_bytes: strings → raw UTF-8; bools → "true"/"false" UTF-8;
 *                  objects/arrays → compact JSON UTF-8 (no spaces)
 *   - parent  = SHA3-256(left || right)
 *   - root is 32 bytes — ML-DSA-65 signs the root
 */

import { createPublicKey, createVerify, createHash } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { logAccess } from "./lib/access-log.mjs";

const TIMEOUT_MS    = 10000;

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type":                 "application/json",
};

function reply(statusCode, body) {
  return { statusCode, headers: CORS, body: JSON.stringify(body, null, 2) };
}

async function fetchWithTimeout(url, opts = {}) {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(TIMEOUT_MS) });
}

// ── URL validation — blocks SSRF via private/loopback addresses ───────────────
function validateUrl(urlStr) {
  if (typeof urlStr !== "string" || urlStr.length > 500) {
    return { ok: false, reason: "INVALID_URL", detail: "URL must be a string under 500 characters" };
  }
  let parsed;
  try { parsed = new URL(urlStr); } catch {
    return { ok: false, reason: "INVALID_URL", detail: "URL could not be parsed" };
  }
  if (parsed.protocol !== "https:") {
    return { ok: false, reason: "INVALID_SCHEME", detail: "Only https:// URLs are accepted" };
  }
  const h = parsed.hostname.toLowerCase();
  const blocked = [
    /^localhost$/,
    /^0\.0\.0\.0$/,
    /^127\./,
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^169\.254\./,
    /^\[?::1\]?$/,
    /^\[?fc/,
    /^\[?fd/,
  ];
  for (const pat of blocked) {
    if (pat.test(h)) {
      return { ok: false, reason: "PRIVATE_ADDRESS", detail: "Private, loopback, and link-local addresses are not permitted" };
    }
  }
  if (!h.includes(".")) {
    return { ok: false, reason: "INVALID_HOSTNAME", detail: "Hostname must be a fully qualified domain name" };
  }
  return { ok: true };
}


// ══════════════════════════════════════════════════════════════════════════════
// Ed25519 — classical path (AGS §15.6)
// ══════════════════════════════════════════════════════════════════════════════

// Canonical serialization (must match aether_ghost_seal.py §15.4.3)
function canonicalBytes(manifest) {
  const ordered = {};

  for (const f of ["aether_version", "beacon_id", "node_url", "addressed_to", "human_visible", "machine_readable"]) {
    if (f in manifest) ordered[f] = manifest[f];
  }

  if (manifest.operator)        ordered.operator        = manifest.operator;
  if (manifest.confidentiality) ordered.confidentiality = { status: manifest.confidentiality.status };
  if (manifest.communication)   ordered.communication   = { endpoint: manifest.communication.endpoint };
  if (manifest.mesh)            ordered.mesh            = {
    registry_url:      manifest.mesh.registry_url,
    specification_url: manifest.mesh.specification_url,
  };

  for (const f of ["topics", "status", "signal", "established"]) {
    if (f in manifest) ordered[f] = manifest[f];
  }

  return Buffer.from(JSON.stringify(ordered, null, undefined), "utf-8");
}

// Node.js requires Ed25519 public keys in SPKI DER format.
// SPKI prefix for Ed25519 (OID 1.3.101.112): 302a300506032b6570032100
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function verifyEd25519(publicKeyHex, signatureHex, messageBuffer) {
  try {
    const pubKeyRaw  = Buffer.from(publicKeyHex, "hex");
    const spkiDer    = Buffer.concat([ED25519_SPKI_PREFIX, pubKeyRaw]);
    const publicKey  = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    const verifier   = createVerify("Ed25519");
    verifier.update(messageBuffer);
    return verifier.verify(publicKey, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}


// ══════════════════════════════════════════════════════════════════════════════
// ML-DSA-65 + Merkle-SHA3-256 — post-quantum path (AGS §15.6.2)
// ══════════════════════════════════════════════════════════════════════════════

function sha3_256(data) {
  return createHash("sha3-256").update(data).digest();
}

// Padding leaf for Merkle tree — SHA3-256 of empty bytes
const MERKLE_PADDING_LEAF = sha3_256(Buffer.alloc(0));

// Canonical field order (same 14 fields as classical path, individually Merkle-hashed)
const CANONICAL_FIELD_NAMES = [
  "aether_version",
  "beacon_id",
  "node_url",
  "addressed_to",
  "human_visible",
  "machine_readable",
  "operator",
  "confidentiality",
  "communication",
  "mesh",
  "topics",
  "status",
  "signal",
  "established",
];

// Serialize a field's value to bytes for Merkle leaf computation
function fieldValueBytes(fieldName, manifest) {
  let val = manifest[fieldName];

  // Apply the same subfield filtering as the classical canonical path
  if (fieldName === "confidentiality" && val != null) {
    val = { status: val.status };
  } else if (fieldName === "communication" && val != null) {
    val = { endpoint: val.endpoint };
  } else if (fieldName === "mesh" && val != null) {
    val = { registry_url: val.registry_url, specification_url: val.specification_url };
  }

  if (typeof val === "boolean") return Buffer.from(String(val), "utf-8");
  if (typeof val === "string")  return Buffer.from(val, "utf-8");
  // object or array → compact JSON (preserves key insertion order from parsed JSON)
  return Buffer.from(JSON.stringify(val, null, undefined), "utf-8");
}

// leaf_i = SHA3-256(utf8(field_name) || 0x00 || value_bytes)
function merkleLeaf(fieldName, valueBytes) {
  return sha3_256(Buffer.concat([
    Buffer.from(fieldName, "utf-8"),
    Buffer.from([0x00]),
    valueBytes,
  ]));
}

// internal node = SHA3-256(left || right)
function merkleParent(left, right) {
  return sha3_256(Buffer.concat([left, right]));
}

// Build Merkle root from an arbitrary number of leaves, padded to next power of 2
function buildMerkleRoot(leaves) {
  let size = 1;
  while (size < leaves.length) size <<= 1;

  const padded = [...leaves];
  while (padded.length < size) padded.push(Buffer.from(MERKLE_PADDING_LEAF));

  let level = padded;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(merkleParent(level[i], level[i + 1]));
    }
    level = next;
  }
  return level[0]; // 32-byte Buffer
}

// Compute the Merkle root over all canonical fields present in manifest
function manifestMerkleRoot(manifest) {
  const leaves = [];
  for (const fieldName of CANONICAL_FIELD_NAMES) {
    if (fieldName in manifest) {
      leaves.push(merkleLeaf(fieldName, fieldValueBytes(fieldName, manifest)));
    }
  }
  return buildMerkleRoot(leaves);
}

// ML-DSA-65 verify: msg is the 32-byte Merkle root
function verifyMLDSA65(publicKeyHex, signatureHex, merkleRoot) {
  try {
    const pubKey = Buffer.from(publicKeyHex, "hex");
    const sig    = Buffer.from(signatureHex,  "hex");
    return ml_dsa65.verify(pubKey, merkleRoot, sig);
  } catch {
    return false;
  }
}


// ══════════════════════════════════════════════════════════════════════════════
// Registry lookup
// ══════════════════════════════════════════════════════════════════════════════
async function lookupRegistry(beacon_id, node_url) {
  try {
    const r = await fetchWithTimeout("https://aetherbeacon.io/aether-registry.json");
    if (!r.ok) return null;
    const registry = await r.json();
    return registry.nodes?.find(n =>
      (beacon_id && n.beacon_id === beacon_id) ||
      (node_url  && n.url === node_url)
    ) || null;
  } catch {
    return null;
  }
}


// ══════════════════════════════════════════════════════════════════════════════
// Handler
// ══════════════════════════════════════════════════════════════════════════════
export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: CORS, body: "" };
  }

  if (event.httpMethod !== "GET") {
    return reply(405, { status: "ERROR", reason: "METHOD_NOT_ALLOWED" });
  }

  const params   = event.queryStringParameters || {};
  const beaconId = params.beacon_id?.trim();
  const nodeUrl  = params.node_url?.trim();

  if (!beaconId && !nodeUrl) {
    return reply(400, {
      status:  "ERROR",
      reason:  "MISSING_PARAMETER",
      message: "Provide ?beacon_id=X or ?node_url=X",
      example: "https://aetherbeacon.io/verify?beacon_id=AEGIS-ALPHA-001",
    });
  }

  if (nodeUrl) {
    const urlCheck = validateUrl(nodeUrl);
    if (!urlCheck.ok) {
      return reply(400, { status: "ERROR", reason: urlCheck.reason, detail: urlCheck.detail });
    }
  }

  // Resolve node URL from registry if only beacon_id supplied
  let targetUrl = nodeUrl;
  if (!targetUrl && beaconId) {
    const entry = await lookupRegistry(beaconId, null);
    if (entry) {
      targetUrl = entry.url;
    } else {
      return reply(404, {
        status:          "NOT_FOUND",
        beacon_id:       beaconId,
        registry_status: "UNREGISTERED",
        message:         "beacon_id not found in AETHER registry. Provide ?node_url= to verify directly.",
      });
    }
  }

  if (!targetUrl.endsWith("/")) targetUrl += "/";

  // Fetch manifest
  let manifest;
  try {
    const r = await fetchWithTimeout(`${targetUrl}aether.json`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    manifest = await r.json();
  } catch (e) {
    return reply(502, {
      status:   "ERROR",
      reason:   "MANIFEST_UNREACHABLE",
      message:  e.message,
      node_url: targetUrl,
    });
  }

  // Check ghost_seal presence
  const gs = manifest.ghost_seal;
  if (!gs) {
    return reply(200, {
      seal_status:     "UNSIGNED",
      beacon_id:       manifest.beacon_id || "UNKNOWN",
      node_url:        targetUrl,
      registry_status: (await lookupRegistry(manifest.beacon_id, targetUrl)) ? "REGISTERED" : "UNREGISTERED",
      message:         "No ghost_seal block found. Beacon has not been ceremonially signed.",
    });
  }

  const { verification_key, signature, signed_at, ceremony_epoch, share_threshold, algorithm } = gs;

  if (!verification_key || !signature) {
    return reply(200, {
      seal_status: "INCOMPLETE",
      beacon_id:   manifest.beacon_id,
      node_url:    targetUrl,
      message:     "ghost_seal present but missing verification_key or signature.",
    });
  }

  const declaredAlgorithm = (algorithm || "Ed25519").trim();

  // ── Route by algorithm ────────────────────────────────────────────────────
  let valid = false;

  if (declaredAlgorithm === "Ed25519") {
    // Classical path — sign over compact canonical JSON
    const manifestCopy = JSON.parse(JSON.stringify(manifest));
    manifestCopy.ghost_seal.signature = null;
    const canonical = canonicalBytes(manifestCopy);
    valid = verifyEd25519(verification_key, signature, canonical);

  } else if (declaredAlgorithm === "ML-DSA-65+Merkle-SHA3-256") {
    // Post-quantum path — sign over Merkle root of canonical fields
    const manifestCopy = JSON.parse(JSON.stringify(manifest));
    manifestCopy.ghost_seal.signature = null;
    const merkleRoot = manifestMerkleRoot(manifestCopy);
    valid = verifyMLDSA65(verification_key, signature, merkleRoot);

  } else {
    return reply(200, {
      seal_status: "UNSUPPORTED_ALGORITHM",
      beacon_id:   manifest.beacon_id,
      node_url:    targetUrl,
      algorithm:   declaredAlgorithm,
      message:     `Unsupported ghost_seal algorithm: ${declaredAlgorithm}. Supported: Ed25519, ML-DSA-65+Merkle-SHA3-256`,
    });
  }

  // Registry lookup
  const registryEntry = await lookupRegistry(manifest.beacon_id, targetUrl);

  const result = {
    seal_status:      valid ? "VERIFIED" : "INVALID",
    beacon_id:        manifest.beacon_id,
    node_url:         targetUrl,
    algorithm:        declaredAlgorithm,
    verification_key: verification_key,
    signed_at:        signed_at,
    ceremony_epoch:   ceremony_epoch,
    share_threshold:  share_threshold,
    registry_status:  registryEntry ? "REGISTERED" : "UNREGISTERED",
    verified_at:      new Date().toISOString(),
  };

  if (!valid) {
    result.message = "Ghost Seal signature verification FAILED. Treat this beacon as UNTRUSTED.";
  } else {
    result.message = "Ghost Seal verified. Beacon manifest is authentic and has not been tampered with.";
    if (registryEntry) {
      result.registry_entry = {
        registered:   registryEntry.registered,
        node_class:   registryEntry.node_class,
        capabilities: registryEntry.capabilities,
      };
    }
  }

  await logAccess({
    endpoint: "/verify",
    event,
    result:   result.seal_status,
    extra: {
      beacon_id:       result.beacon_id,
      registry_status: result.registry_status,
      algorithm:       result.algorithm,
    },
  });

  return reply(200, result);
};
