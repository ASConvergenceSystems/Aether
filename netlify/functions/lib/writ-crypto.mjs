/**
 * AETHER WRIT — cryptographic primitives
 *
 * Canonical commitment construction and Ghost Seal signature verification
 * for delegation issuance, revocation, and receipt sealing.
 */

import { createHash, createHmac, timingSafeEqual, createPublicKey, createVerify } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";

const WRIT_SIGNING_SECRET = process.env.WRIT_SIGNING_SECRET;

// ── Hashing helpers ───────────────────────────────────────────────────────────
export function sha3_256hex(data) {
  return createHash("sha3-256").update(data).digest("hex");
}

export function sha256hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

// ── Canonical commitment for a delegation ─────────────────────────────────────
// Deterministic: sorts scope and constraints keys, excludes the signing block.
export function delegationCommitment(fields) {
  const str = [
    fields.delegation_id,
    fields.issued_at,
    fields.issuer_beacon_id,
    fields.delegate_beacon_id,
    JSON.stringify(fields.scope,       Object.keys(fields.scope      ).sort()),
    JSON.stringify(fields.constraints, Object.keys(fields.constraints).sort()),
    String(fields.depth),
    String(fields.parent_delegation_id ?? "null"),
  ].join("|");
  return sha3_256hex(Buffer.from(str, "utf-8"));
}

// ── Canonical commitment for a revocation ────────────────────────────────────
export function revocationCommitment(fields) {
  const str = [
    fields.revocation_id,
    fields.revoked_at,
    fields.delegation_id,
    fields.revoking_beacon_id,
    fields.reason ?? "",
  ].join("|");
  return sha3_256hex(Buffer.from(str, "utf-8"));
}

// ── Ghost Seal signature verification ────────────────────────────────────────
// Routes to Ed25519 or ML-DSA-65 based on the algorithm field.
// verificationKeyHex: hex-encoded public key (from registry, not caller-supplied)
// signatureHex:       hex-encoded signature
// commitmentHex:      hex-encoded 32-byte SHA3-256 commitment

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function verifyGhostSeal(algorithm, verificationKeyHex, signatureHex, commitmentHex) {
  try {
    const commitment = Buffer.from(commitmentHex, "hex");
    const signature  = Buffer.from(signatureHex,  "hex");
    const vkBytes    = Buffer.from(verificationKeyHex, "hex");

    if (algorithm === "ML-DSA-65+Merkle-SHA3-256") {
      return ml_dsa65.verify(new Uint8Array(vkBytes), new Uint8Array(commitment), new Uint8Array(signature));
    }

    if (algorithm === "Ed25519") {
      const spki    = Buffer.concat([ED25519_SPKI_PREFIX, vkBytes]);
      const pubKey  = createPublicKey({ key: spki, format: "der", type: "spki" });
      const verifier = createVerify("Ed25519");
      verifier.update(commitment);
      return verifier.verify(pubKey, signature);
    }

    return false; // unknown algorithm
  } catch {
    return false;
  }
}

// ── Attestation HMAC proof ────────────────────────────────────────────────────
// Server-side: compute and verify the hmac_proof stored on an attestation.
// Uses the attestor's mesh token (re-derived from MESH_TOKEN_SECRET).
export function computeAttestationHmac(meshToken, attestationId, proposalId, attestorBeaconId, vote, attestedAt) {
  return createHmac("sha3-256", meshToken)
    .update(`${attestationId}|${proposalId}|${attestorBeaconId}|${vote}|${attestedAt}`)
    .digest("hex");
}

export function verifyAttestationHmac(meshToken, hmacProof, attestationId, proposalId, attestorBeaconId, vote, attestedAt) {
  try {
    const expected  = Buffer.from(computeAttestationHmac(meshToken, attestationId, proposalId, attestorBeaconId, vote, attestedAt), "hex");
    const presented = Buffer.from(hmacProof, "hex");
    if (expected.length !== presented.length) return false;
    return timingSafeEqual(expected, presented);
  } catch {
    return false;
  }
}

// ── Delegation chain digest ───────────────────────────────────────────────────
// Used in attestations to bind the vote to a specific chain.
// delegations: array of delegation objects in chain order (leaf → root)
export function delegationChainDigest(delegations) {
  const commitments = delegations.map(d => d.signing.commitment);
  return sha3_256hex(Buffer.from(commitments.join(""), "hex"));
}

// ── Receipt server seal ───────────────────────────────────────────────────────
export function sealReceipt(receiptId, proposalId, issuedAt, quorumAchieved) {
  if (!WRIT_SIGNING_SECRET) throw new Error("WRIT_SIGNING_SECRET not configured");
  const commitment = sha3_256hex(Buffer.from(
    receiptId + "|" + proposalId + "|" + issuedAt + "|" + JSON.stringify(quorumAchieved),
    "utf-8"
  ));
  const seal = createHmac("sha3-256", WRIT_SIGNING_SECRET)
    .update(commitment)
    .digest("hex");
  return { commitment, seal };
}

export function verifyReceiptSeal(receipt) {
  if (!WRIT_SIGNING_SECRET) return false;
  try {
    const { commitment, seal } = sealReceipt(
      receipt.receipt_id,
      receipt.proposal_id,
      receipt.issued_at,
      receipt.quorum_achieved,
    );
    const expected  = Buffer.from(seal, "hex");
    const presented = Buffer.from(receipt.server_seal.seal, "hex");
    if (expected.length !== presented.length) return false;
    return timingSafeEqual(expected, presented) &&
           commitment === receipt.server_seal.commitment;
  } catch {
    return false;
  }
}

// ── Chain hash helpers ────────────────────────────────────────────────────────
export function chainHash(prevHash, id, timestamp) {
  return sha256hex(Buffer.from(`${prevHash}|${id}|${timestamp}`, "utf-8"));
}
