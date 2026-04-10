/**
 * AETHER Beacon Verification Function
 * GET /verify?beacon_id=X  — or —  GET /verify?node_url=X
 *
 * Fetches the beacon's aether.json, reconstructs canonical form,
 * verifies the Ed25519 Ghost Seal, and returns a structured trust report.
 */

import { createPublicKey, createVerify } from "node:crypto";

const TIMEOUT_MS    = 10000;
const REGISTRY_PATH = "aether-registry.json";

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

// ── Canonical serialization (must match aether_ghost_seal.py §15.4.3) ─────────
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


// ── Ed25519 verification ──────────────────────────────────────────────────────
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


// ── Registry lookup ───────────────────────────────────────────────────────────
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


// ── Handler ───────────────────────────────────────────────────────────────────
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

  // Resolve node URL
  let targetUrl = nodeUrl;
  if (!targetUrl && beaconId) {
    // Look up in registry first
    const entry = await lookupRegistry(beaconId, null);
    if (entry) {
      targetUrl = entry.url;
    } else {
      return reply(404, {
        status:        "NOT_FOUND",
        beacon_id:     beaconId,
        registry_status: "UNREGISTERED",
        message:       "beacon_id not found in AETHER registry. Provide ?node_url= to verify directly.",
      });
    }
  }

  // Normalize URL
  if (!targetUrl.endsWith("/")) targetUrl += "/";

  // Fetch manifest
  let manifest;
  try {
    const r = await fetchWithTimeout(`${targetUrl}aether.json`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    manifest = await r.json();
  } catch (e) {
    return reply(502, {
      status:  "ERROR",
      reason:  "MANIFEST_UNREACHABLE",
      message: e.message,
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

  // Reconstruct canonical form (exclude ghost_seal.signature per §15.4.3)
  const manifestCopy = JSON.parse(JSON.stringify(manifest));
  manifestCopy.ghost_seal.signature = null;
  const canonical = canonicalBytes(manifestCopy);

  // Verify
  const valid = verifyEd25519(verification_key, signature, canonical);

  // Registry lookup
  const registryEntry = await lookupRegistry(manifest.beacon_id, targetUrl);

  const result = {
    seal_status:      valid ? "VERIFIED" : "INVALID",
    beacon_id:        manifest.beacon_id,
    node_url:         targetUrl,
    algorithm:        algorithm || "Ed25519",
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
        registered:  registryEntry.registered,
        node_class:  registryEntry.node_class,
        capabilities: registryEntry.capabilities,
      };
    }
  }

  return reply(valid ? 200 : 200, result);
};
