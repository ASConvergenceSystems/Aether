/**
 * AETHER Mesh Token — shared auth utilities
 *
 * Per-node tokens are derived server-side:
 *   token = HMAC-SHA3-256(MESH_TOKEN_SECRET, beacon_id)  → 32 bytes / 64 hex
 *
 * The secret never leaves the Netlify environment.
 * A node obtains its token by hitting GET /mesh-token/{beacon_id},
 * which returns the token encrypted to their registered public key.
 * Only the holder of the private key can decrypt and use it.
 *
 * Verification is stateless — no DB lookup, just re-derive and compare.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

const MESH_TOKEN_SECRET = process.env.MESH_TOKEN_SECRET;

/**
 * Derive the canonical per-node mesh token for a given beacon_id.
 * Throws if MESH_TOKEN_SECRET is not configured.
 */
export function deriveMeshToken(beaconId) {
  if (!MESH_TOKEN_SECRET) {
    throw new Error("MESH_TOKEN_SECRET environment variable is not set");
  }
  return createHmac("sha3-256", MESH_TOKEN_SECRET)
    .update(beaconId, "utf-8")
    .digest("hex"); // 64 hex chars (32 bytes)
}

/**
 * Timing-safe verification of a presented mesh token against the expected
 * token for a given beacon_id.  Returns false on any mismatch or error.
 */
export function verifyMeshToken(beaconId, presentedHex) {
  if (!MESH_TOKEN_SECRET || !beaconId || !presentedHex) return false;
  try {
    const expected  = Buffer.from(deriveMeshToken(beaconId), "hex");
    const presented = Buffer.from(presentedHex, "hex");
    if (expected.length !== presented.length) return false;
    return timingSafeEqual(expected, presented);
  } catch {
    return false;
  }
}

/**
 * Extract the bearer token from an Authorization header.
 */
export function extractBearer(event) {
  const h = event.headers["authorization"] || event.headers["Authorization"] || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

/**
 * Extract beacon_id from X-Beacon-ID header.
 */
export function extractBeaconId(event) {
  return (event.headers["x-beacon-id"] || event.headers["X-Beacon-ID"] || "").trim();
}
