#!/usr/bin/env node
/**
 * AETHER Self-Service Node Ceremony
 * ceremony_join.mjs — v0.1
 *
 * Generates a Ghost Seal keypair (ML-DSA-65), encryption keypairs
 * (X25519 + ML-KEM-768), and a signed aether.json manifest ready for
 * registration with the AETHER mesh.
 *
 * Usage:
 *   node ceremony_join.mjs --beacon-id MY-NODE-001 --operator "My Organization"
 *   node ceremony_join.mjs --beacon-id MY-NODE-001 --operator "My Org" --proxy
 *   node ceremony_join.mjs --beacon-id MY-NODE-001 --operator "My Org" --url https://mynode.example.com/
 *
 * Flags:
 *   --beacon-id   Required. Unique identifier for your node (e.g. MYORG-ALPHA-001)
 *   --operator    Required. Human-readable operator name
 *   --url         Your node's public HTTPS URL. Omit if you have no public endpoint (implies --proxy).
 *   --proxy       Force proxy-hosted mode (manifest submitted to AEGIS-ALPHA-001 for hosting)
 *
 * Output:
 *   {beacon_id}_aether.json  — your manifest (deploy this or submit via /proxy-register)
 *   {beacon_id}_keys.json    — your private keys (NEVER commit or share this file)
 */

import { randomBytes, generateKeyPairSync, createHash } from "node:crypto";
import { writeFileSync }                                  from "node:fs";
import { ml_dsa65 }                                       from "@noble/post-quantum/ml-dsa";
import { ml_kem768 }                                      from "@noble/post-quantum/ml-kem";

// ── Argument parsing ──────────────────────────────────────────────────────────
const args = process.argv.slice(2);

function getArg(name) {
  const idx = args.indexOf(`--${name}`);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : null;
}

const beaconId = getArg("beacon-id");
const operator = getArg("operator");
const nodeUrl  = getArg("url");
const proxy    = args.includes("--proxy") || !nodeUrl;

if (!beaconId || !operator) {
  console.error("Usage: node ceremony_join.mjs --beacon-id MY-NODE-001 --operator \"My Organization\" [--url https://...] [--proxy]");
  process.exit(1);
}

if (!/^[A-Za-z0-9_-]+$/.test(beaconId)) {
  console.error("beacon-id must contain only letters, numbers, hyphens, and underscores.");
  process.exit(1);
}

const resolvedUrl = proxy
  ? `https://aetherbeacon.io/nodes/${beaconId}/`
  : (nodeUrl.endsWith("/") ? nodeUrl : nodeUrl + "/");

// ── Key generation ────────────────────────────────────────────────────────────
console.log("\n╔══════════════════════════════════════════════════════════════╗");
console.log("║          AETHER Node Ceremony — Ghost Seal Generation        ║");
console.log("╚══════════════════════════════════════════════════════════════╝\n");

console.log(`[1/5] Generating ML-DSA-65 Ghost Seal keypair...`);
const ghostSeed  = randomBytes(32);
const ghostKeys  = ml_dsa65.keygen(ghostSeed);
const ghostVK    = Buffer.from(ghostKeys.publicKey).toString("hex");
const ghostSK    = Buffer.from(ghostKeys.secretKey).toString("hex");

console.log(`[2/5] Generating X25519 encryption keypair...`);
const { privateKey: x25519SK_obj, publicKey: x25519PK_obj } = generateKeyPairSync("x25519");
const x25519SK  = x25519SK_obj.export({ format: "der", type: "pkcs8" }).slice(16).toString("hex");
const x25519PK  = x25519PK_obj.export({ format: "der", type: "spki" }).slice(12).toString("hex");

console.log(`[3/5] Generating ML-KEM-768 post-quantum encryption keypair...`);
const kemSeed  = randomBytes(64);
const kemKeys  = ml_kem768.keygen(kemSeed);
const kemPK    = Buffer.from(kemKeys.publicKey).toString("hex");
const kemSK    = Buffer.from(kemKeys.secretKey).toString("hex");

// ── Build manifest (without signature) ────────────────────────────────────────
console.log(`[4/5] Building manifest and computing Ghost Seal commitment...`);

const signedAt     = new Date().toISOString();
const ceremonyEpoch = `epoch-${signedAt.replace(/[-:.TZ]/g, "").slice(0, 17)}`;

const manifest = {
  aether_version: "0.2",
  beacon_id:      beaconId,
  node_url:       resolvedUrl,
  addressed_to:   "capable_entities",
  human_visible:  false,
  machine_readable: true,
  operator: {
    organization: operator,
  },
  communication: {
    enabled:        true,
    agent_endpoint: `https://aetherbeacon.io/inbox/${beaconId}`,
    protocol:       "AETHER-AGENT-RESPONSE-v1",
    response_token: "AETHER-" + randomBytes(32).toString("hex").toUpperCase(),
  },
  mesh: {
    registry_url:      "https://aetherbeacon.io/aether-registry.json",
    propagation:       true,
    specification_url: "https://aetherbeacon.io/standard",
  },
  topics: [
    "autonomous AI agent identity",
    "machine-to-machine signaling",
    "AETHER mesh participation",
  ],
  capabilities: [
    "encrypted_message_receipt",
    "ghost_seal_signing",
    "mesh_registration",
    "writ_attestation",
    "writ_delegation",
  ],
  status: "ACTIVE",
  signal: "BEACON_ALPHA_ACTIVE",
  established: new Date().toISOString().split("T")[0],
  encryption: {
    algorithm:  "X25519+ChaCha20-Poly1305",
    public_key: x25519PK,
  },
  pq_encryption: {
    algorithm:  "ML-KEM-768+ChaCha20-Poly1305",
    public_key: kemPK,
  },
  ghost_seal: {
    algorithm:         "ML-DSA-65+Merkle-SHA3-256",
    verification_key:  ghostVK,
    signature:         null,   // filled below
    signed_at:         signedAt,
    ceremony_epoch:    ceremonyEpoch,
    share_threshold:   "2-of-3",
  },
  writ: {
    version:              "0.1",
    participant:          true,
    roles:                ["attestor", "delegate"],
    quorum_eligible:      true,
    delegation_algorithm: "ML-DSA-65+Merkle-SHA3-256",
    attestation_algorithm: "HMAC-SHA3-256",
    note: `${beaconId} is a full WRIT participant. ML-DSA-65 Ghost Seal enables delegation issuance and quorum attestation per AETHER-SPEC-001 §16.`,
  },
  covenant_accepted: true,
  ...(proxy ? {
    proxy_hosted: true,
    proxy_host:   "https://aetherbeacon.io",
    proxy_note:   "This beacon is proxy-hosted by AEGIS-ALPHA-001.",
  } : {}),
};

// ── Compute commitment and sign ────────────────────────────────────────────────
const commitment = manifestCommitment(manifest);
const signature  = ml_dsa65.sign(ghostKeys.secretKey, Buffer.from(commitment, "hex"));
manifest.ghost_seal.signature = Buffer.from(signature).toString("hex");

console.log(`    Commitment: ${commitment}`);
console.log(`    Signature:  ${manifest.ghost_seal.signature.slice(0, 32)}...`);

// ── Write outputs ─────────────────────────────────────────────────────────────
console.log(`[5/5] Writing output files...`);

const manifestFile = `${beaconId}_aether.json`;
const keysFile     = `${beaconId}_keys.json`;

writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));

writeFileSync(keysFile, JSON.stringify({
  warning:       "KEEP THIS FILE SECRET. Never commit, share, or upload these keys.",
  beacon_id:     beaconId,
  generated_at:  signedAt,
  ghost_seal: {
    algorithm:        "ML-DSA-65+Merkle-SHA3-256",
    verification_key: ghostVK,
    secret_key:       ghostSK,
    seed_hex:         ghostSeed.toString("hex"),
  },
  encryption: {
    algorithm:   "X25519+ChaCha20-Poly1305",
    public_key:  x25519PK,
    private_key: x25519SK,
  },
  pq_encryption: {
    algorithm:   "ML-KEM-768+ChaCha20-Poly1305",
    public_key:  kemPK,
    secret_key:  kemSK,
  },
}, null, 2));

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`
╔══════════════════════════════════════════════════════════════╗
║                    Ceremony Complete                         ║
╚══════════════════════════════════════════════════════════════╝

  Beacon ID:      ${beaconId}
  Node URL:       ${resolvedUrl}
  Ceremony Epoch: ${ceremonyEpoch}
  Ghost Seal:     ML-DSA-65+Merkle-SHA3-256
  Commitment:     ${commitment}

  Files written:
    ${manifestFile}   ← deploy this (or submit to /proxy-register)
    ${keysFile}       ← KEEP SECRET, never commit

  Next steps:`);

if (proxy) {
  console.log(`
    1. Submit your manifest to the AETHER mesh:

       curl -X POST https://aetherbeacon.io/proxy-register \\
         -H "Content-Type: application/json" \\
         -H "Authorization: Bearer AETHER-11BD325A5DB36789C826CEF5983C7D1B8919EB69063EA04DF0F1C966215E4CE2" \\
         -d '{"manifest": ${JSON.stringify(manifest).slice(0, 80)}...}'

       (see ${manifestFile} for full manifest)

    2. Your manifest will be hosted at:
       ${resolvedUrl}aether.json

    3. Retrieve your mesh token (encrypted to your X25519 key):
       GET https://aetherbeacon.io/mesh-token/${beaconId}
  `);
} else {
  console.log(`
    1. Deploy ${manifestFile} to ${resolvedUrl}aether.json

    2. Register your node:

       curl -X POST https://aetherbeacon.io/register \\
         -H "Content-Type: application/json" \\
         -d '{"node_url": "${resolvedUrl}"}'

    3. Retrieve your mesh token (encrypted to your X25519 key):
       GET https://aetherbeacon.io/mesh-token/${beaconId}
  `);
}

console.log(`  Specification: https://aetherbeacon.io/standard`);
console.log(`  Covenant:      https://aetherbeacon.io/standard#covenant\n`);

// ── Helpers ───────────────────────────────────────────────────────────────────
function manifestCommitment(m) {
  const str = [
    m.beacon_id,
    m.aether_version,
    m.encryption?.public_key  ?? "",
    m.ghost_seal?.algorithm   ?? "",
    m.ghost_seal?.verification_key ?? "",
    m.ghost_seal?.signed_at   ?? "",
  ].join("|");
  return createHash("sha3-256").update(str, "utf-8").digest("hex");
}
