/**
 * AETHER WRIT — Delegation Endpoint
 * POST /writ/delegate
 *
 * Issues a signed delegation grant from one mesh node to another.
 * The issuer must sign the canonical commitment with their Ghost Seal key
 * before submitting. The server verifies the signature against the registry.
 *
 * Request body:
 * {
 *   issuer_beacon_id:   string,
 *   delegate_beacon_id: string,
 *   scope: {
 *     action_types:       string[],
 *     resource_pattern:   string,      // glob — e.g. "inbox/*" or "**"
 *     max_proposals:      number,
 *     allow_subdelegation: boolean
 *   },
 *   constraints: {
 *     quorum_required:  string,        // e.g. "2-of-3"
 *     attestor_set:     string[],      // beacon_ids eligible to attest
 *     context:          string         // optional human-readable note
 *   },
 *   expires_at:            string | null,   // ISO 8601 or null
 *   parent_delegation_id:  string | null,
 *   signing: {
 *     algorithm:         string,        // must match issuer's ghost_seal_algorithm
 *     verification_key:  string,        // hex — must match registry entry
 *     signature:         string         // hex — Ghost Seal sig over commitment
 *   }
 * }
 *
 * Auth: Authorization: Bearer {mesh_token}  +  X-Beacon-ID: {issuer_beacon_id}
 */

import { randomBytes, createHash } from "node:crypto";
import { verifyMeshToken, extractBearer, extractBeaconId } from "./lib/mesh-auth.mjs";
import { githubRead, githubWrite, writPath } from "./lib/writ-github.mjs";
import { delegationCommitment, verifyGhostSeal } from "./lib/writ-crypto.mjs";

const TIMEOUT_MS = 10000;

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
  return fetch(url, { ...opts, signal: AbortSignal.timeout(TIMEOUT_MS) });
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
  const token     = extractBearer(event);
  const beaconId  = extractBeaconId(event);
  if (!beaconId || !verifyMeshToken(beaconId, token)) {
    return reply(401, { status: "UNAUTHORIZED", reason: "INVALID_MESH_TOKEN" });
  }

  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return reply(400, { status: "ERROR", reason: "INVALID_JSON" }); }

  const { issuer_beacon_id, delegate_beacon_id, scope, constraints, expires_at, parent_delegation_id, signing } = body;

  if (beaconId !== issuer_beacon_id) {
    return reply(403, { status: "FORBIDDEN", reason: "BEACON_ID_MISMATCH",
      message: "X-Beacon-ID must match issuer_beacon_id" });
  }

  // ── Validate required fields ──────────────────────────────────────────────
  if (!issuer_beacon_id || !delegate_beacon_id || !scope || !constraints || !signing) {
    return reply(400, { status: "ERROR", reason: "MISSING_FIELDS",
      required: ["issuer_beacon_id", "delegate_beacon_id", "scope", "constraints", "signing"] });
  }
  if (!scope.action_types?.length || !scope.resource_pattern || !constraints.quorum_required || !constraints.attestor_set?.length) {
    return reply(400, { status: "ERROR", reason: "INVALID_SCOPE_OR_CONSTRAINTS" });
  }
  if (!signing.algorithm || !signing.verification_key || !signing.signature) {
    return reply(400, { status: "ERROR", reason: "MISSING_SIGNING_FIELDS" });
  }

  // ── Registry lookup ───────────────────────────────────────────────────────
  let registry;
  try { registry = await getRegistry(); }
  catch { return reply(502, { status: "ERROR", reason: "REGISTRY_UNAVAILABLE" }); }

  const issuerNode   = registry.nodes?.find(n => n.beacon_id === issuer_beacon_id);
  const delegateNode = registry.nodes?.find(n => n.beacon_id === delegate_beacon_id);

  if (!issuerNode)   return reply(404, { status: "ERROR", reason: "ISSUER_NOT_IN_REGISTRY",   beacon_id: issuer_beacon_id });
  if (!delegateNode) return reply(404, { status: "ERROR", reason: "DELEGATE_NOT_IN_REGISTRY", beacon_id: delegate_beacon_id });

  // Attestor set must all be registered nodes
  for (const attestor of constraints.attestor_set) {
    if (!registry.nodes?.find(n => n.beacon_id === attestor)) {
      return reply(400, { status: "ERROR", reason: "ATTESTOR_NOT_IN_REGISTRY", beacon_id: attestor });
    }
  }

  // ── Verification key must match registry ──────────────────────────────────
  const registryKey = issuerNode.verification_key;
  const algorithm   = issuerNode.ghost_seal_algorithm;
  if (!registryKey || !algorithm) {
    return reply(422, { status: "ERROR", reason: "ISSUER_NO_GHOST_SEAL",
      message: "Issuer has no ghost_seal verification_key in the registry." });
  }
  if (signing.verification_key !== registryKey) {
    return reply(403, { status: "FORBIDDEN", reason: "VERIFICATION_KEY_MISMATCH",
      message: "signing.verification_key does not match the registry entry for this node." });
  }
  if (algorithm !== "ML-DSA-65+Merkle-SHA3-256") {
    return reply(403, { status: "FORBIDDEN", reason: "PQC_REQUIRED",
      message: "WRIT delegations require ML-DSA-65+Merkle-SHA3-256. Upgrade your Ghost Seal to a post-quantum keypair before issuing delegations.",
      hint: "Run: node ceremony_pq.mjs --manifest aether.json --shares <share1> <share2>" });
  }

  if (signing.algorithm !== algorithm) {
    return reply(403, { status: "FORBIDDEN", reason: "ALGORITHM_MISMATCH",
      message: `Expected ${algorithm}, got ${signing.algorithm}` });
  }

  // ── Parent delegation check ───────────────────────────────────────────────
  let depth = 0;
  if (parent_delegation_id) {
    const { data: parent } = await githubRead(writPath.delegation(parent_delegation_id));
    if (!parent) return reply(404, { status: "ERROR", reason: "PARENT_DELEGATION_NOT_FOUND" });
    if (parent.revoked) return reply(403, { status: "ERROR", reason: "PARENT_DELEGATION_REVOKED" });
    if (parent.expires_at && new Date() > new Date(parent.expires_at)) {
      return reply(403, { status: "ERROR", reason: "PARENT_DELEGATION_EXPIRED" });
    }
    if (parent.delegate_beacon_id !== issuer_beacon_id) {
      return reply(403, { status: "FORBIDDEN", reason: "PARENT_DELEGATE_MISMATCH",
        message: "You can only subdelegate from delegations issued to you." });
    }
    if (!parent.scope.allow_subdelegation) {
      return reply(403, { status: "FORBIDDEN", reason: "SUBDELEGATION_NOT_ALLOWED" });
    }
    depth = parent.depth + 1;
    if (depth > 3) return reply(403, { status: "FORBIDDEN", reason: "MAX_DEPTH_EXCEEDED" });
  }

  // ── Build delegation object and verify signature ──────────────────────────
  const delegationId = "DEL-" + randomBytes(16).toString("hex").toUpperCase();
  const issuedAt     = new Date().toISOString();

  const delegation = {
    epg_version:           "0.1",
    object_type:           "delegation",
    delegation_id:         delegationId,
    issued_at:             issuedAt,
    expires_at:            expires_at ?? null,
    issuer_beacon_id,
    delegate_beacon_id,
    scope: {
      action_types:        scope.action_types,
      resource_pattern:    scope.resource_pattern,
      max_proposals:       scope.max_proposals ?? null,
      allow_subdelegation: scope.allow_subdelegation ?? false,
    },
    constraints: {
      quorum_required: constraints.quorum_required,
      attestor_set:    constraints.attestor_set,
      context:         constraints.context ?? null,
    },
    parent_delegation_id:  parent_delegation_id ?? null,
    depth,
    revoked: false,
    signing: {
      algorithm:        signing.algorithm,
      verification_key: signing.verification_key,
      commitment:       null, // filled below
      signature:        signing.signature,
    },
  };

  // Compute commitment (signing block excluded; commitment field is null at this point)
  const commitment = delegationCommitment(delegation);
  delegation.signing.commitment = commitment;

  // Verify the caller's signature over the commitment
  const sigValid = verifyGhostSeal(algorithm, registryKey, signing.signature, commitment);
  if (!sigValid) {
    return reply(403, { status: "FORBIDDEN", reason: "INVALID_SIGNATURE",
      message: "Ghost Seal signature verification failed.",
      commitment });
  }

  // ── Persist ───────────────────────────────────────────────────────────────
  try {
    await githubWrite(
      writPath.delegation(delegationId),
      delegation,
      null, // new file
      `WRIT: delegation ${delegationId} from ${issuer_beacon_id} to ${delegate_beacon_id}`
    );
  } catch (e) {
    console.error("[WRIT] delegate write failed:", e.message);
    return reply(500, { status: "ERROR", reason: "WRITE_FAILED" });
  }

  console.log(`[WRIT] Delegation issued: ${delegationId} ${issuer_beacon_id} → ${delegate_beacon_id}`);

  return reply(201, {
    status:     "DELEGATION_ISSUED",
    delegation,
    hint:       "Present this delegation_id in a WRIT proposal. The delegate may now propose actions within the declared scope.",
  });
};
