/**
 * AETHER WRIT — Receipt Endpoint
 * GET /writ/receipt/{proposal_id}
 *
 * Returns the provenance receipt for a completed proposal.
 * If quorum has been reached but the receipt hasn't been generated yet,
 * generates it lazily. Returns 202 if quorum is still pending.
 *
 * Auth: Authorization: Bearer {mesh_token}  +  X-Beacon-ID: {your_beacon_id}
 */

import { randomBytes } from "node:crypto";
import { verifyMeshToken, extractBearer, extractBeaconId, deriveMeshToken } from "./lib/mesh-auth.mjs";
import { githubRead, githubWrite, githubUpdate, writPath, DEFAULT_INDEX } from "./lib/writ-github.mjs";
import { sealReceipt, chainHash, verifyReceiptSeal } from "./lib/writ-crypto.mjs";
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
  if (event.httpMethod !== "GET")     return reply(405, { status: "ERROR", reason: "METHOD_NOT_ALLOWED" });

  // ── Auth ──────────────────────────────────────────────────────────────────
  const token    = extractBearer(event);
  const beaconId = extractBeaconId(event);
  if (!beaconId || !verifyMeshToken(beaconId, token)) {
    return reply(401, { status: "UNAUTHORIZED", reason: "INVALID_MESH_TOKEN" });
  }

  const pathParts  = (event.path || "").split("/").filter(Boolean);
  const proposalId = pathParts[pathParts.length - 1];

  if (!proposalId || proposalId === "receipt") {
    return reply(400, { status: "ERROR", reason: "MISSING_PROPOSAL_ID",
      message: "Path must be /writ/receipt/{proposal_id}" });
  }

  // ── Check for existing receipt first ─────────────────────────────────────
  const { data: existing } = await githubRead(writPath.receipt(proposalId));
  if (existing) {
    return reply(200, {
      status:       "OK",
      receipt:      existing,
      seal_valid:   verifyReceiptSeal(existing),
    });
  }

  // ── Load proposal ─────────────────────────────────────────────────────────
  const { data: proposal } = await githubRead(writPath.proposal(proposalId));
  if (!proposal) return reply(404, { status: "ERROR", reason: "PROPOSAL_NOT_FOUND", proposal_id: proposalId });

  if (proposal.status === "REJECTED") return reply(410, { status: "REJECTED", proposal_id: proposalId });
  if (proposal.status === "EXPIRED")  return reply(410, { status: "EXPIRED",  proposal_id: proposalId });

  // ── Load attestations and evaluate quorum ────────────────────────────────
  const { data: attDoc } = await githubRead(writPath.attestations(proposalId));
  const attestations = attDoc?.attestations ?? [];

  let registry;
  try { registry = await getRegistry(); }
  catch { return reply(502, { status: "ERROR", reason: "REGISTRY_UNAVAILABLE" }); }

  const registryIndex = new Map(registry.nodes?.map(n => [n.beacon_id, n]) ?? []);

  const delegations = new Map();
  for (const id of proposal.delegation_chain) {
    const { data } = await githubRead(writPath.delegation(id));
    if (data) delegations.set(id, data);
  }

  const quorumResult = evaluateQuorum(proposal, attestations, delegations, registryIndex);

  if (!quorumResult.satisfied) {
    const [N] = proposal.quorum_spec.required.split("-of-").map(Number);
    return reply(202, {
      status:        "QUORUM_PENDING",
      proposal_id:   proposalId,
      quorum_status: {
        required:   proposal.quorum_spec.required,
        approvals:  quorumResult.approvals.length,
        rejections: quorumResult.rejections.length,
        remaining:  Math.max(0, N - quorumResult.approvals.length),
        deadline:   proposal.quorum_spec.deadline,
      },
    });
  }

  if (quorumResult.outcome !== "APPROVED") {
    return reply(410, {
      status:      quorumResult.outcome,
      proposal_id: proposalId,
      approvals:   quorumResult.approvals.length,
      rejections:  quorumResult.rejections.length,
    });
  }

  // ── Generate receipt lazily ───────────────────────────────────────────────
  const receiptId  = "RCP-" + randomBytes(16).toString("hex").toUpperCase();
  const issuedAt   = new Date().toISOString();

  const quorumAchieved = {
    spec:         proposal.quorum_spec.required,
    approvals:    quorumResult.approvals.length,
    rejections:   quorumResult.rejections.length,
    attestations: [...quorumResult.approvals, ...quorumResult.rejections].map(a => ({
      attestation_id:     a.attestation_id,
      attestor_beacon_id: a.attestor_beacon_id,
      vote:               a.vote,
      attested_at:        a.attested_at,
    })),
  };

  const { data: index } = await githubRead(writPath.index());
  const prevHash     = index?.receipt_chain_tip ?? "WRIT-RECEIPT-GENESIS";
  const rcpChainHash = chainHash(prevHash, receiptId, issuedAt);

  let serverSeal;
  try { serverSeal = sealReceipt(receiptId, proposalId, issuedAt, quorumAchieved); }
  catch { serverSeal = { commitment: null, seal: null }; }

  const receipt = {
    writ_version:       "0.1",
    object_type:        "receipt",
    receipt_id:         receiptId,
    proposal_id:        proposalId,
    issued_at:          issuedAt,
    outcome:            "APPROVED",
    proposer_beacon_id: proposal.proposer_beacon_id,
    action:             proposal.action,
    delegation_chain:   proposal.delegation_chain,
    quorum_achieved:    quorumAchieved,
    chain_hash:         rcpChainHash,
    prev_hash:          prevHash,
    server_seal:        serverSeal,
  };

  try {
    await githubWrite(writPath.receipt(proposalId), receipt, null,
      `WRIT: receipt ${receiptId} for ${proposalId} (lazy)`);
  } catch (e) {
    if (e.message.includes("422") || e.message.includes("409")) {
      const { data: raceReceipt } = await githubRead(writPath.receipt(proposalId));
      if (raceReceipt) return reply(200, { status: "OK", receipt: raceReceipt, seal_valid: verifyReceiptSeal(raceReceipt) });
    }
    console.error("[WRIT] lazy receipt write failed:", e.message);
    return reply(500, { status: "ERROR", reason: "RECEIPT_WRITE_FAILED" });
  }

  // Update index
  try {
    await githubUpdate(writPath.index(),
      (idx) => {
        const current = idx ?? { ...DEFAULT_INDEX };
        current.last_updated      = issuedAt;
        current.open_proposals    = (current.open_proposals ?? []).filter(id => id !== proposalId);
        current.receipt_chain_tip = rcpChainHash;
        current.receipt_count     = (current.receipt_count ?? 0) + 1;
        return current;
      },
      `WRIT: index update for receipt ${receiptId}`,
      { ...DEFAULT_INDEX }
    );
  } catch { /* non-fatal */ }

  return reply(200, {
    status:     "OK",
    receipt,
    seal_valid: verifyReceiptSeal(receipt),
  });
};
