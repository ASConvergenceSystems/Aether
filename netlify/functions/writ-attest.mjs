/**
 * AETHER WRIT — Attestation Endpoint
 * POST /writ/attest
 *
 * A mesh node votes on a pending proposal. Once quorum is reached,
 * a provenance receipt is generated inline.
 *
 * Request body:
 * {
 *   attestor_beacon_id: string,
 *   proposal_id:        string,
 *   vote:               "APPROVE" | "REJECT",
 *   rationale:          string    // optional but encouraged
 * }
 *
 * Auth: Authorization: Bearer {mesh_token}  +  X-Beacon-ID: {attestor_beacon_id}
 */

import { randomBytes } from "node:crypto";
import { verifyMeshToken, extractBearer, extractBeaconId, deriveMeshToken } from "./lib/mesh-auth.mjs";
import { githubRead, githubWrite, githubUpdate, writPath, DEFAULT_INDEX } from "./lib/writ-github.mjs";
import { computeAttestationHmac, delegationChainDigest, sealReceipt, chainHash } from "./lib/writ-crypto.mjs";
import { evaluateQuorum } from "./lib/writ-verify.mjs";

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

async function generateReceipt(proposal, attestations, delegations, quorumResult) {
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

  // Chain hash — links receipts into an append-only sequence
  const { data: index } = await githubRead(writPath.index());
  const prevHash        = index?.receipt_chain_tip ?? "WRIT-RECEIPT-GENESIS";
  const rcpChainHash    = chainHash(prevHash, receiptId, issuedAt);

  let serverSeal;
  try { serverSeal = sealReceipt(receiptId, proposal.proposal_id, issuedAt, quorumAchieved); }
  catch { serverSeal = { commitment: null, seal: null, error: "WRIT_SIGNING_SECRET not configured" }; }

  const receipt = {
    writ_version:       "0.1",
    object_type:        "receipt",
    receipt_id:         receiptId,
    proposal_id:        proposal.proposal_id,
    issued_at:          issuedAt,
    outcome:            quorumResult.outcome,
    proposer_beacon_id: proposal.proposer_beacon_id,
    action:             proposal.action,
    delegation_chain:   proposal.delegation_chain,
    quorum_achieved:    quorumAchieved,
    chain_hash:         rcpChainHash,
    prev_hash:          prevHash,
    server_seal:        serverSeal,
  };

  // Write receipt (once — if 409, another request beat us; read back theirs)
  try {
    await githubWrite(
      writPath.receipt(proposal.proposal_id), receipt, null,
      `WRIT: receipt ${receiptId} for ${proposal.proposal_id} — ${quorumResult.outcome}`
    );
  } catch (e) {
    if (e.message.includes("422") || e.message.includes("409")) {
      // Already written by concurrent request — read it back
      const { data: existing } = await githubRead(writPath.receipt(proposal.proposal_id));
      if (existing) return existing;
    }
    throw e;
  }

  // Update proposal status
  try {
    const { data: prop, sha } = await githubRead(writPath.proposal(proposal.proposal_id));
    if (prop && prop.status === "PENDING") {
      prop.status = quorumResult.outcome;
      await githubWrite(
        writPath.proposal(proposal.proposal_id), prop, sha,
        `WRIT: proposal ${proposal.proposal_id} → ${quorumResult.outcome}`
      );
    }
  } catch { /* non-fatal — receipt is the authoritative record */ }

  // Update index
  try {
    await githubUpdate(
      writPath.index(),
      (idx) => {
        const current = idx ?? { ...DEFAULT_INDEX };
        current.last_updated      = issuedAt;
        current.open_proposals    = (current.open_proposals ?? []).filter(id => id !== proposal.proposal_id);
        current.receipt_chain_tip = rcpChainHash;
        current.receipt_count     = (current.receipt_count ?? 0) + 1;
        return current;
      },
      `WRIT: index update for receipt ${receiptId}`,
      { ...DEFAULT_INDEX }
    );
  } catch { /* non-fatal */ }

  return receipt;
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

  const { attestor_beacon_id, proposal_id, vote, rationale } = body;

  if (beaconId !== attestor_beacon_id) {
    return reply(403, { status: "FORBIDDEN", reason: "BEACON_ID_MISMATCH" });
  }
  if (!proposal_id || !vote) {
    return reply(400, { status: "ERROR", reason: "MISSING_FIELDS", required: ["attestor_beacon_id", "proposal_id", "vote"] });
  }
  if (!["APPROVE", "REJECT"].includes(vote)) {
    return reply(400, { status: "ERROR", reason: "INVALID_VOTE", allowed: ["APPROVE", "REJECT"] });
  }

  // ── Load proposal ─────────────────────────────────────────────────────────
  const { data: proposal } = await githubRead(writPath.proposal(proposal_id));
  if (!proposal) return reply(404, { status: "ERROR", reason: "PROPOSAL_NOT_FOUND", proposal_id });
  if (proposal.status !== "PENDING") {
    return reply(409, { status: "ERROR", reason: "PROPOSAL_NOT_PENDING", current_status: proposal.status });
  }
  if (new Date() > new Date(proposal.quorum_spec.deadline)) {
    return reply(410, { status: "ERROR", reason: "PROPOSAL_EXPIRED" });
  }

  // ── Check eligibility ─────────────────────────────────────────────────────
  if (!proposal.quorum_spec.eligible_attestors.includes(attestor_beacon_id)) {
    return reply(403, { status: "FORBIDDEN", reason: "NOT_ELIGIBLE_ATTESTOR",
      eligible: proposal.quorum_spec.eligible_attestors });
  }

  // ── Registry ──────────────────────────────────────────────────────────────
  let registry;
  try { registry = await getRegistry(); }
  catch { return reply(502, { status: "ERROR", reason: "REGISTRY_UNAVAILABLE" }); }

  const registryIndex = new Map(registry.nodes?.map(n => [n.beacon_id, n]) ?? []);

  // ── Load existing attestations and check for duplicate vote ──────────────
  const { data: attDoc, sha: attSha } = await githubRead(writPath.attestations(proposal_id));
  const existingAttestations = attDoc?.attestations ?? [];

  if (existingAttestations.some(a => a.attestor_beacon_id === attestor_beacon_id)) {
    return reply(409, { status: "ERROR", reason: "ALREADY_VOTED",
      message: "This node has already submitted an attestation for this proposal." });
  }

  // ── Load delegation chain for digest ─────────────────────────────────────
  const delegations = new Map();
  for (const id of proposal.delegation_chain) {
    const { data } = await githubRead(writPath.delegation(id));
    if (data) delegations.set(id, data);
  }

  const chainDigest = delegations.size === proposal.delegation_chain.length
    ? delegationChainDigest([...proposal.delegation_chain.map(id => delegations.get(id))])
    : null;

  // ── Build attestation ─────────────────────────────────────────────────────
  const attestationId = "ATT-" + randomBytes(16).toString("hex").toUpperCase();
  const attestedAt    = new Date().toISOString();
  const meshToken     = deriveMeshToken(attestor_beacon_id);

  const hmacProof = computeAttestationHmac(
    meshToken, attestationId, proposal_id, attestor_beacon_id, vote, attestedAt
  );

  const attestation = {
    writ_version:            "0.1",
    object_type:             "attestation",
    attestation_id:          attestationId,
    proposal_id,
    attested_at:             attestedAt,
    attestor_beacon_id,
    vote,
    rationale:               rationale ? String(rationale).slice(0, 500) : null,
    delegation_chain_digest: chainDigest,
    hmac_proof:              hmacProof,
  };

  // ── Append attestation (retry on SHA 409) ─────────────────────────────────
  const updatedAttestations = [...existingAttestations, attestation];
  const attDocUpdated = {
    writ_version:  "0.1",
    proposal_id,
    attestations:  updatedAttestations,
    last_updated:  attestedAt,
  };

  let writeSuccess = false;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const { sha: freshSha } = await githubRead(writPath.attestations(proposal_id));
      await githubWrite(
        writPath.attestations(proposal_id), attDocUpdated, freshSha,
        `WRIT: attestation ${attestationId} on ${proposal_id} — ${vote}`
      );
      writeSuccess = true;
      break;
    } catch (e) {
      if (e.message.includes("409") && attempt < 2) continue;
      console.error("[WRIT] attestation write failed:", e.message);
      return reply(500, { status: "ERROR", reason: "WRITE_FAILED" });
    }
  }
  if (!writeSuccess) return reply(500, { status: "ERROR", reason: "WRITE_FAILED_AFTER_RETRIES" });

  // ── Evaluate quorum ───────────────────────────────────────────────────────
  const quorumResult = evaluateQuorum(proposal, updatedAttestations, delegations, registryIndex);

  console.log(`[WRIT] Attestation: ${attestationId} on ${proposal_id} — ${vote} by ${attestor_beacon_id}`);

  // ── Generate receipt if quorum satisfied ──────────────────────────────────
  if (quorumResult.satisfied) {
    let receipt;
    try {
      receipt = await generateReceipt(proposal, updatedAttestations, delegations, quorumResult);
    } catch (e) {
      console.error("[WRIT] receipt generation failed:", e.message);
      // Return attestation success even if receipt fails — can be retrieved via GET /writ/receipt
    }

    return reply(200, {
      status:        "ATTESTED",
      attestation,
      quorum_status: {
        satisfied: true,
        outcome:   quorumResult.outcome,
        approvals: quorumResult.approvals.length,
        rejections: quorumResult.rejections.length,
        required:  proposal.quorum_spec.required,
      },
      receipt: receipt ?? null,
      message: receipt
        ? `Quorum reached. WRIT ${quorumResult.outcome}. Receipt: ${receipt.receipt_id}`
        : `Quorum reached (${quorumResult.outcome}) but receipt generation failed. Retrieve via GET /writ/receipt/${proposal_id}`,
    });
  }

  const [N] = proposal.quorum_spec.required.split("-of-").map(Number);

  return reply(200, {
    status:        "ATTESTED",
    attestation,
    quorum_status: {
      satisfied:  false,
      outcome:    "PENDING",
      approvals:  quorumResult.approvals.length,
      rejections: quorumResult.rejections.length,
      required:   proposal.quorum_spec.required,
      remaining:  Math.max(0, N - quorumResult.approvals.length),
    },
  });
};
