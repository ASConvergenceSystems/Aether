/**
 * AETHER WRIT — delegation chain validation and quorum evaluation
 *
 * Pure functions — no I/O. All required data is passed in.
 * Called by epg-attest.mjs, epg-receipt.mjs, and epg-propose.mjs.
 */

import { verifyGhostSeal, verifyAttestationHmac, delegationCommitment, delegationChainDigest } from "./writ-crypto.mjs";
import { deriveMeshToken } from "./mesh-auth.mjs";

const MAX_DELEGATION_DEPTH = 3;

// ── Glob-style resource pattern matching ─────────────────────────────────────
// Supports * (single segment) and ** (any path)
export function matchesResourcePattern(pattern, resource) {
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "<<GLOBSTAR>>")
    .replace(/\*/g, "[^/]*")
    .replace(/<<GLOBSTAR>>/g, ".*");
  return new RegExp(`^${regexStr}$`).test(resource);
}

// ── Scope containment: child scope must be a subset of parent scope ───────────
export function scopeContains(parentScope, childScope) {
  const violations = [];

  // action_types: child must be a subset of parent
  if (parentScope.action_types && childScope.action_types) {
    for (const t of childScope.action_types) {
      if (!parentScope.action_types.includes(t)) {
        violations.push(`action_type "${t}" not in parent scope`);
      }
    }
  }

  // resource_pattern: child pattern must be at least as restrictive
  // Simple check: child resource pattern must match against parent pattern
  if (parentScope.resource_pattern && childScope.resource_pattern) {
    if (!matchesResourcePattern(parentScope.resource_pattern, childScope.resource_pattern.replace(/[*]+/g, "test"))) {
      // Heuristic: if the child's pattern couldn't possibly be a subset, flag it
      // Full containment proof is complex; we apply a conservative check
      if (!childScope.resource_pattern.startsWith(parentScope.resource_pattern.replace(/\*.*/, ""))) {
        violations.push(`resource_pattern "${childScope.resource_pattern}" not contained within "${parentScope.resource_pattern}"`);
      }
    }
  }

  // max_proposals: child must be <= parent
  if (parentScope.max_proposals != null && childScope.max_proposals != null) {
    if (childScope.max_proposals > parentScope.max_proposals) {
      violations.push(`max_proposals ${childScope.max_proposals} exceeds parent ${parentScope.max_proposals}`);
    }
  }

  return { covered: violations.length === 0, violations };
}

// ── Validate a full delegation chain ─────────────────────────────────────────
// delegations: Map<delegation_id, delegation_object>
// revokedIds:  Set<delegation_id>
// registryIndex: Map<beacon_id, registry_node_entry>
// proposerBeaconId: the node submitting the proposal
// actionType: string
// targetResource: string
//
// Returns { valid: boolean, reason?: string }
export function validateDelegationChain(chainIds, delegations, revokedIds, registryIndex, proposerBeaconId, actionType, targetResource) {
  if (!chainIds || chainIds.length === 0) {
    return { valid: false, reason: "EMPTY_CHAIN" };
  }
  if (chainIds.length > MAX_DELEGATION_DEPTH) {
    return { valid: false, reason: `CHAIN_TOO_DEEP: max ${MAX_DELEGATION_DEPTH}` };
  }

  // Validate each link
  for (let i = 0; i < chainIds.length; i++) {
    const d = delegations.get(chainIds[i]);
    if (!d) return { valid: false, reason: `DELEGATION_NOT_FOUND: ${chainIds[i]}` };

    // Revocation check
    if (revokedIds.has(chainIds[i])) {
      return { valid: false, reason: `DELEGATION_REVOKED: ${chainIds[i]}` };
    }

    // Expiry check
    if (d.expires_at && new Date() > new Date(d.expires_at)) {
      return { valid: false, reason: `DELEGATION_EXPIRED: ${chainIds[i]}` };
    }

    // Depth check
    if (d.depth !== i) {
      return { valid: false, reason: `DEPTH_MISMATCH: ${chainIds[i]} expected depth ${i}, got ${d.depth}` };
    }

    // Chain linkage: each delegation's delegate must be the next delegation's issuer
    if (i < chainIds.length - 1) {
      const next = delegations.get(chainIds[i + 1]);
      if (!next) return { valid: false, reason: `DELEGATION_NOT_FOUND: ${chainIds[i + 1]}` };
      if (d.issuer_beacon_id !== next.delegate_beacon_id) {
        return { valid: false, reason: `CHAIN_BREAK: ${chainIds[i]}.issuer !== ${chainIds[i+1]}.delegate` };
      }
      if (!d.scope.allow_subdelegation) {
        return { valid: false, reason: `SUBDELEGATION_NOT_ALLOWED: ${chainIds[i]}` };
      }
      // Scope containment: child (i) must be within parent (i+1)
      const containment = scopeContains(next.scope, d.scope);
      if (!containment.covered) {
        return { valid: false, reason: `SCOPE_VIOLATION: ${containment.violations.join("; ")}` };
      }
    }

    // Verify Ghost Seal signature
    const registryNode = registryIndex.get(d.issuer_beacon_id);
    if (!registryNode) {
      return { valid: false, reason: `ISSUER_NOT_IN_REGISTRY: ${d.issuer_beacon_id}` };
    }
    // Ground truth key comes from registry, not the delegation itself
    const registryKey = registryNode.verification_key;
    const algorithm   = registryNode.ghost_seal_algorithm || registryNode.algorithm;
    if (!registryKey || !algorithm) {
      return { valid: false, reason: `ISSUER_NO_VERIFICATION_KEY: ${d.issuer_beacon_id}` };
    }
    // The submitted key must match the registry key
    if (d.signing.verification_key !== registryKey) {
      return { valid: false, reason: `VERIFICATION_KEY_MISMATCH: ${d.issuer_beacon_id}` };
    }
    // Recompute commitment and verify signature
    const expectedCommitment = delegationCommitment(d);
    if (expectedCommitment !== d.signing.commitment) {
      return { valid: false, reason: `COMMITMENT_MISMATCH: ${chainIds[i]}` };
    }
    const sigValid = verifyGhostSeal(algorithm, registryKey, d.signing.signature, d.signing.commitment);
    if (!sigValid) {
      return { valid: false, reason: `INVALID_SIGNATURE: ${chainIds[i]}` };
    }
  }

  // Leaf delegation (index 0) must authorize the proposer
  const leaf = delegations.get(chainIds[0]);
  if (leaf.delegate_beacon_id !== proposerBeaconId) {
    return { valid: false, reason: `LEAF_DELEGATE_MISMATCH: expected ${proposerBeaconId}, got ${leaf.delegate_beacon_id}` };
  }

  // Action type must be in leaf scope
  if (leaf.scope.action_types && !leaf.scope.action_types.includes(actionType)) {
    return { valid: false, reason: `ACTION_NOT_IN_SCOPE: ${actionType}` };
  }

  // Target resource must match leaf scope pattern
  if (leaf.scope.resource_pattern && targetResource) {
    if (!matchesResourcePattern(leaf.scope.resource_pattern, targetResource)) {
      return { valid: false, reason: `RESOURCE_NOT_IN_SCOPE: ${targetResource}` };
    }
  }

  return { valid: true };
}

// ── Quorum evaluation ─────────────────────────────────────────────────────────
// Pure function — does not read from storage.
// proposal: proposal object
// attestations: array of attestation objects
// delegations: Map<id, delegation_object> (for chain digest verification)
// registryIndex: Map<beacon_id, registry_node_entry>
//
// Returns { satisfied, outcome, approvals, rejections, errors }
export function evaluateQuorum(proposal, attestations, delegations, registryIndex) {
  const [N, M] = proposal.quorum_spec.required.split("-of-").map(Number);
  const eligibleSet = new Set(proposal.quorum_spec.eligible_attestors);

  const approvals  = [];
  const rejections = [];
  const errors     = [];
  const seen       = new Set();

  for (const a of attestations) {
    // Basic checks
    if (a.proposal_id !== proposal.proposal_id) {
      errors.push(`${a.attestation_id}: proposal_id mismatch`);
      continue;
    }
    if (!eligibleSet.has(a.attestor_beacon_id)) {
      errors.push(`${a.attestation_id}: attestor not in eligible set`);
      continue;
    }
    if (!registryIndex.has(a.attestor_beacon_id)) {
      errors.push(`${a.attestation_id}: attestor not in registry`);
      continue;
    }
    if (seen.has(a.attestor_beacon_id)) {
      errors.push(`${a.attestation_id}: duplicate vote from ${a.attestor_beacon_id}`);
      continue;
    }
    // Deadline check
    if (new Date(a.attested_at) > new Date(proposal.quorum_spec.deadline)) {
      errors.push(`${a.attestation_id}: attested after deadline`);
      continue;
    }

    // HMAC proof verification
    let meshToken;
    try { meshToken = deriveMeshToken(a.attestor_beacon_id); } catch {
      errors.push(`${a.attestation_id}: could not derive mesh token`);
      continue;
    }
    const hmacValid = verifyAttestationHmac(
      meshToken, a.hmac_proof,
      a.attestation_id, a.proposal_id, a.attestor_beacon_id, a.vote, a.attested_at
    );
    if (!hmacValid) {
      errors.push(`${a.attestation_id}: invalid hmac_proof`);
      continue;
    }

    // Delegation chain digest verification
    if (delegations && proposal.delegation_chain.length > 0) {
      const chain = proposal.delegation_chain.map(id => delegations.get(id)).filter(Boolean);
      if (chain.length === proposal.delegation_chain.length) {
        const expectedDigest = delegationChainDigest(chain);
        if (a.delegation_chain_digest !== expectedDigest) {
          errors.push(`${a.attestation_id}: delegation_chain_digest mismatch`);
          continue;
        }
      }
    }

    seen.add(a.attestor_beacon_id);
    if (a.vote === "APPROVE") approvals.push(a);
    else if (a.vote === "REJECT") rejections.push(a);
  }

  // Quorum decision
  if (approvals.length >= N) {
    return { satisfied: true, outcome: "APPROVED", approvals, rejections, errors };
  }
  if (rejections.length > (M - N)) {
    return { satisfied: true, outcome: "REJECTED", approvals, rejections, errors };
  }
  if (new Date() > new Date(proposal.quorum_spec.deadline)) {
    return { satisfied: true, outcome: "EXPIRED", approvals, rejections, errors };
  }

  return { satisfied: false, outcome: "PENDING", approvals, rejections, errors };
}
