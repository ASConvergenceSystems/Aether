/**
 * AETHER WRIT — Proposal Endpoint
 * POST /writ/propose
 *
 * A delegated node submits an action for mesh quorum attestation.
 * The delegation chain is validated before the proposal is stored.
 *
 * Request body:
 * {
 *   proposer_beacon_id: string,
 *   action: {
 *     type:             string,
 *     description:      string,
 *     target_resource:  string,
 *     parameters:       object,
 *     estimated_impact: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
 *   },
 *   delegation_chain:      string[],   // ordered leaf → root delegation IDs
 *   quorum_deadline_hours: number      // default 24
 * }
 *
 * Auth: Authorization: Bearer {mesh_token}  +  X-Beacon-ID: {proposer_beacon_id}
 */

import { randomBytes } from "node:crypto";
import { verifyMeshToken, extractBearer, extractBeaconId, deriveMeshToken } from "./lib/mesh-auth.mjs";
import { githubRead, githubWrite, githubUpdate, writPath, DEFAULT_INDEX } from "./lib/writ-github.mjs";
import { chainHash, sha256hex, computeAttestationHmac } from "./lib/writ-crypto.mjs";
import { validateDelegationChain } from "./lib/writ-verify.mjs";

const TIMEOUT_MS = 10000;
const MAX_DEADLINE_HOURS = 168; // 7 days

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
  const token    = extractBearer(event);
  const beaconId = extractBeaconId(event);
  if (!beaconId || !verifyMeshToken(beaconId, token)) {
    return reply(401, { status: "UNAUTHORIZED", reason: "INVALID_MESH_TOKEN" });
  }

  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return reply(400, { status: "ERROR", reason: "INVALID_JSON" }); }

  const { proposer_beacon_id, action, delegation_chain, quorum_deadline_hours } = body;

  if (beaconId !== proposer_beacon_id) {
    return reply(403, { status: "FORBIDDEN", reason: "BEACON_ID_MISMATCH" });
  }
  if (!action?.type || !action?.description || !delegation_chain?.length) {
    return reply(400, { status: "ERROR", reason: "MISSING_FIELDS",
      required: ["proposer_beacon_id", "action.type", "action.description", "delegation_chain"] });
  }

  // ── Registry ──────────────────────────────────────────────────────────────
  let registry;
  try { registry = await getRegistry(); }
  catch { return reply(502, { status: "ERROR", reason: "REGISTRY_UNAVAILABLE" }); }

  const registryIndex = new Map(registry.nodes?.map(n => [n.beacon_id, n]) ?? []);

  // ── Load delegation chain from storage ────────────────────────────────────
  const delegations = new Map();
  for (const id of delegation_chain) {
    if (!/^DEL-[A-F0-9]+$/i.test(id)) {
      return reply(400, { status: "ERROR", reason: "INVALID_DELEGATION_ID", id });
    }
    const { data } = await githubRead(writPath.delegation(id));
    if (!data) return reply(404, { status: "ERROR", reason: "DELEGATION_NOT_FOUND", id });
    delegations.set(id, data);
  }

  // ── Load revocations ──────────────────────────────────────────────────────
  const { data: revocationsDoc } = await githubRead(writPath.revocations());
  const revokedIds = new Set((revocationsDoc?.revocations ?? []).map(r => r.delegation_id));

  // ── Validate chain ────────────────────────────────────────────────────────
  const chainValid = validateDelegationChain(
    delegation_chain, delegations, revokedIds, registryIndex,
    proposer_beacon_id, action.type, action.target_resource ?? ""
  );
  if (!chainValid.valid) {
    return reply(403, { status: "FORBIDDEN", reason: "INVALID_DELEGATION_CHAIN",
      detail: chainValid.reason });
  }

  // ── Build quorum spec from leaf delegation ────────────────────────────────
  const leaf = delegations.get(delegation_chain[0]);
  const deadlineHours = Math.min(quorum_deadline_hours ?? 24, MAX_DEADLINE_HOURS);
  const deadline = new Date(Date.now() + deadlineHours * 3600 * 1000).toISOString();

  const quorumSpec = {
    required:           leaf.constraints.quorum_required,
    eligible_attestors: leaf.constraints.attestor_set,
    deadline,
  };

  // ── Build proposal ────────────────────────────────────────────────────────
  const proposalId = "PROP-" + randomBytes(16).toString("hex").toUpperCase();
  const createdAt  = new Date().toISOString();

  // HMAC commitment: binds proposer identity to action content
  const meshToken      = deriveMeshToken(proposer_beacon_id);
  const hmacCommitment = computeAttestationHmac(
    meshToken, proposalId, proposalId, proposer_beacon_id, action.type, createdAt
  );

  // Chain hash: links proposals into an append-only sequence
  const { data: index } = await githubRead(writPath.index());
  const prevHash = index?.receipt_chain_tip ?? "WRIT-PROPOSAL-GENESIS";
  const propChainHash = chainHash(prevHash, proposalId, createdAt);

  const proposal = {
    writ_version:       "0.1",
    object_type:        "proposal",
    proposal_id:        proposalId,
    created_at:         createdAt,
    expires_at:         deadline,
    proposer_beacon_id,
    action: {
      type:             action.type,
      description:      String(action.description).slice(0, 500),
      target_resource:  action.target_resource ?? null,
      parameters:       action.parameters ?? {},
      estimated_impact: action.estimated_impact ?? "MEDIUM",
    },
    delegation_chain,
    quorum_spec:        quorumSpec,
    status:             "PENDING",
    hmac_commitment:    hmacCommitment,
    chain_hash:         propChainHash,
    prev_hash:          prevHash,
  };

  // ── Persist proposal ──────────────────────────────────────────────────────
  try {
    await githubWrite(
      writPath.proposal(proposalId), proposal, null,
      `WRIT: proposal ${proposalId} from ${proposer_beacon_id}`
    );
  } catch (e) {
    console.error("[WRIT] proposal write failed:", e.message);
    return reply(500, { status: "ERROR", reason: "WRITE_FAILED" });
  }

  // ── Update index ──────────────────────────────────────────────────────────
  try {
    await githubUpdate(
      writPath.index(),
      (current) => {
        const idx = current ?? { ...DEFAULT_INDEX };
        idx.last_updated    = createdAt;
        idx.proposal_count  = (idx.proposal_count ?? 0) + 1;
        idx.open_proposals  = [...(idx.open_proposals ?? []), proposalId];
        return idx;
      },
      `WRIT: index update for proposal ${proposalId}`,
      { ...DEFAULT_INDEX }
    );
  } catch (e) {
    console.error("[WRIT] index update failed:", e.message); // non-fatal
  }

  console.log(`[WRIT] Proposal: ${proposalId} from ${proposer_beacon_id} — ${action.type}`);

  return reply(201, {
    status:   "PROPOSAL_CREATED",
    proposal,
    next_step: `Eligible attestors: ${quorumSpec.eligible_attestors.join(", ")}. POST /writ/attest to vote.`,
  });
};
