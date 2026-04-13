/**
 * AETHER WRIT — Revocation Endpoint
 * POST /writ/revoke
 *
 * Revokes a delegation. Only the original issuer may revoke.
 * Requires a Ghost Seal signature over the revocation commitment.
 *
 * Request body:
 * {
 *   revoking_beacon_id: string,
 *   delegation_id:      string,
 *   reason:             string,
 *   signing: {
 *     algorithm:  string,
 *     signature:  string   // hex — Ghost Seal sig over revocation commitment
 *   }
 * }
 *
 * Auth: Authorization: Bearer {mesh_token}  +  X-Beacon-ID: {revoking_beacon_id}
 */

import { randomBytes } from "node:crypto";
import { verifyMeshToken, extractBearer, extractBeaconId } from "./lib/mesh-auth.mjs";
import { githubRead, githubWrite, githubUpdate, writPath } from "./lib/writ-github.mjs";
import { revocationCommitment, verifyGhostSeal } from "./lib/writ-crypto.mjs";

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Beacon-ID",
  "Content-Type":                 "application/json",
};

function reply(statusCode, body) {
  return { statusCode, headers: CORS, body: JSON.stringify(body, null, 2) };
}

async function fetchWithTimeout(url, opts = {}) {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(10000) });
}

async function getRegistry() {
  const r = await fetchWithTimeout("https://aetherbeacon.io/aether-registry.json");
  if (!r.ok) throw new Error("registry unavailable");
  return r.json();
}

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: CORS, body: "" };
  if (event.httpMethod !== "POST")    return reply(405, { status: "ERROR", reason: "METHOD_NOT_ALLOWED" });

  // ── Auth ──────────────────────────────────────────────────────────────────
  const token    = extractBearer(event);
  const beaconId = extractBeaconId(event);
  if (!beaconId || !verifyMeshToken(beaconId, token)) {
    return reply(401, { status: "UNAUTHORIZED", reason: "INVALID_MESH_TOKEN" });
  }

  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return reply(400, { status: "ERROR", reason: "INVALID_JSON" }); }

  const { revoking_beacon_id, delegation_id, reason, signing } = body;

  if (beaconId !== revoking_beacon_id) {
    return reply(403, { status: "FORBIDDEN", reason: "BEACON_ID_MISMATCH" });
  }
  if (!delegation_id || !signing?.signature || !signing?.algorithm) {
    return reply(400, { status: "ERROR", reason: "MISSING_FIELDS",
      required: ["revoking_beacon_id", "delegation_id", "signing.algorithm", "signing.signature"] });
  }

  // ── Load delegation ───────────────────────────────────────────────────────
  const { data: delegation } = await githubRead(writPath.delegation(delegation_id));
  if (!delegation) return reply(404, { status: "ERROR", reason: "DELEGATION_NOT_FOUND", delegation_id });
  if (delegation.revoked) return reply(409, { status: "ERROR", reason: "ALREADY_REVOKED" });

  // Only the issuer may revoke
  if (delegation.issuer_beacon_id !== revoking_beacon_id) {
    return reply(403, { status: "FORBIDDEN", reason: "NOT_ISSUER",
      message: "Only the original issuer may revoke a delegation." });
  }

  // ── Registry — get issuer's verification key ──────────────────────────────
  let registry;
  try { registry = await getRegistry(); }
  catch { return reply(502, { status: "ERROR", reason: "REGISTRY_UNAVAILABLE" }); }

  const issuerNode = registry.nodes?.find(n => n.beacon_id === revoking_beacon_id);
  if (!issuerNode) return reply(404, { status: "ERROR", reason: "REVOKER_NOT_IN_REGISTRY" });

  const registryKey = issuerNode.verification_key;
  const algorithm   = issuerNode.ghost_seal_algorithm;
  if (!registryKey || !algorithm) {
    return reply(422, { status: "ERROR", reason: "NO_VERIFICATION_KEY" });
  }
  if (signing.algorithm !== algorithm) {
    return reply(403, { status: "FORBIDDEN", reason: "ALGORITHM_MISMATCH",
      expected: algorithm });
  }

  // ── Build revocation and verify signature ─────────────────────────────────
  const revocationId = "REV-" + randomBytes(16).toString("hex").toUpperCase();
  const revokedAt    = new Date().toISOString();

  const revocation = {
    writ_version:       "0.1",
    object_type:        "revocation",
    revocation_id:      revocationId,
    revoked_at:         revokedAt,
    delegation_id,
    revoking_beacon_id,
    reason:             reason ? String(reason).slice(0, 500) : null,
    signing: {
      algorithm,
      commitment: null, // filled below
      signature:  signing.signature,
    },
  };

  const commitment = revocationCommitment(revocation);
  revocation.signing.commitment = commitment;

  const sigValid = verifyGhostSeal(algorithm, registryKey, signing.signature, commitment);
  if (!sigValid) {
    return reply(403, { status: "FORBIDDEN", reason: "INVALID_SIGNATURE",
      message: "Ghost Seal signature verification failed.",
      commitment });
  }

  // ── Append to revocations log ─────────────────────────────────────────────
  try {
    await githubUpdate(
      writPath.revocations(),
      (doc) => {
        const current = doc ?? { writ_version: "0.1", revocations: [] };
        current.revocations = [...(current.revocations ?? []), revocation];
        current.last_updated = revokedAt;
        return current;
      },
      `WRIT: revocation ${revocationId} for delegation ${delegation_id}`,
      { writ_version: "0.1", revocations: [] }
    );
  } catch (e) {
    console.error("[WRIT] revocation log write failed:", e.message);
    return reply(500, { status: "ERROR", reason: "WRITE_FAILED" });
  }

  // ── Mark delegation as revoked ────────────────────────────────────────────
  try {
    const { data: del, sha } = await githubRead(writPath.delegation(delegation_id));
    if (del) {
      del.revoked    = true;
      del.revoked_at = revokedAt;
      await githubWrite(
        writPath.delegation(delegation_id), del, sha,
        `WRIT: delegation ${delegation_id} revoked by ${revoking_beacon_id}`
      );
    }
  } catch (e) {
    console.error("[WRIT] delegation revoke update failed:", e.message); // non-fatal — revocations.json is authoritative
  }

  console.log(`[WRIT] Revocation: ${revocationId} — delegation ${delegation_id} by ${revoking_beacon_id}`);

  return reply(200, {
    status:     "REVOKED",
    revocation,
    message:    "Delegation revoked. All pending proposals using this delegation chain will fail attestation.",
  });
};
