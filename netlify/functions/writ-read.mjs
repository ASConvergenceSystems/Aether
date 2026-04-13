/**
 * AETHER WRIT — Read Endpoints
 *
 * GET /writ/proposal/{proposal_id}   — read a proposal + attestations + quorum status
 * GET /writ/delegation/{id}          — read a delegation (with revocation status)
 * GET /writ/index                    — read the WRIT index
 *
 * Auth: Authorization: Bearer {mesh_token}  +  X-Beacon-ID: {your_beacon_id}
 */

import { verifyMeshToken, extractBearer, extractBeaconId } from "./lib/mesh-auth.mjs";
import { githubRead, writPath } from "./lib/writ-github.mjs";
import { evaluateQuorum } from "./lib/writ-verify.mjs";

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Beacon-ID",
  "Content-Type":                 "application/json",
};

function reply(statusCode, body) {
  return { statusCode, headers: CORS, body: JSON.stringify(body, null, 2) };
}

async function getRegistry() {
  const r = await fetch("https://aetherbeacon.io/aether-registry.json",
    { signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error("registry unavailable");
  return r.json();
}

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: CORS, body: "" };
  if (event.httpMethod !== "GET")     return reply(405, { status: "ERROR", reason: "METHOD_NOT_ALLOWED" });

  // ── Auth ──────────────────────────────────────────────────────────────────
  const token    = extractBearer(event);
  const beaconId = extractBeaconId(event);
  if (!beaconId || !verifyMeshToken(beaconId, token)) {
    return reply(401, { status: "UNAUTHORIZED", reason: "INVALID_MESH_TOKEN" });
  }

  const pathParts = (event.path || "").split("/").filter(Boolean);
  // pathParts: ["writ", "proposal"|"delegation"|"index", id?]
  const section   = pathParts[1];
  const id        = pathParts[2];

  // ── GET /writ/index ───────────────────────────────────────────────────────
  if (section === "index") {
    const { data } = await githubRead(writPath.index());
    return reply(200, { status: "OK", index: data ?? { writ_index_version: "0.1", empty: true } });
  }

  // ── GET /writ/proposal/{id} ───────────────────────────────────────────────
  if (section === "proposal") {
    if (!id) return reply(400, { status: "ERROR", reason: "MISSING_PROPOSAL_ID" });

    const { data: proposal } = await githubRead(writPath.proposal(id));
    if (!proposal) return reply(404, { status: "ERROR", reason: "PROPOSAL_NOT_FOUND", proposal_id: id });

    const { data: attDoc }   = await githubRead(writPath.attestations(id));
    const attestations       = attDoc?.attestations ?? [];

    let quorumStatus;
    try {
      let registry;
      try { registry = await getRegistry(); } catch { registry = { nodes: [] }; }
      const registryIndex = new Map(registry.nodes?.map(n => [n.beacon_id, n]) ?? []);

      const delegations = new Map();
      for (const delId of proposal.delegation_chain ?? []) {
        const { data } = await githubRead(writPath.delegation(delId));
        if (data) delegations.set(delId, data);
      }

      const result = evaluateQuorum(proposal, attestations, delegations, registryIndex);
      const [N, M] = proposal.quorum_spec.required.split("-of-").map(Number);
      quorumStatus = {
        required:   proposal.quorum_spec.required,
        approvals:  result.approvals.length,
        rejections: result.rejections.length,
        pending:    M - result.approvals.length - result.rejections.length,
        satisfied:  result.satisfied,
        outcome:    result.outcome,
        remaining:  Math.max(0, N - result.approvals.length),
        deadline:   proposal.quorum_spec.deadline,
      };
    } catch (e) {
      quorumStatus = { error: e.message };
    }

    return reply(200, { status: "OK", proposal, attestations, quorum_status: quorumStatus });
  }

  // ── GET /writ/delegation/{id} ─────────────────────────────────────────────
  if (section === "delegation") {
    if (!id) return reply(400, { status: "ERROR", reason: "MISSING_DELEGATION_ID" });

    const { data: delegation } = await githubRead(writPath.delegation(id));
    if (!delegation) return reply(404, { status: "ERROR", reason: "DELEGATION_NOT_FOUND", delegation_id: id });

    const { data: revocationsDoc } = await githubRead(writPath.revocations());
    const revoked = (revocationsDoc?.revocations ?? []).some(r => r.delegation_id === id);

    return reply(200, { status: "OK", delegation: { ...delegation, revoked } });
  }

  return reply(400, { status: "ERROR", reason: "UNKNOWN_PATH",
    message: "Valid paths: /writ/index, /writ/proposal/{id}, /writ/delegation/{id}" });
};
