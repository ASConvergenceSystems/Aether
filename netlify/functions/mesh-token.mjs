/**
 * AETHER Mesh Token Dispensary
 * GET /mesh-token/{beacon_id}
 *
 * Issues a per-node mesh token, encrypted to the node's registered public key.
 * Only the node holding the corresponding private key can decrypt and use it.
 *
 * Token = HMAC-SHA3-256(MESH_TOKEN_SECRET, beacon_id)
 *   — unique per node, verified statelessly on every API call
 *   — MESH_TOKEN_SECRET lives only in Netlify env vars, never in any file
 *
 * Security properties:
 *   - Unregistered nodes cannot obtain a token (no registry entry → no manifest fetch)
 *   - Nodes without an encryption keypair cannot obtain a token (no public key to encrypt to)
 *   - The token is unique per beacon_id — a leaked token affects only one node
 *   - Rotating MESH_TOKEN_SECRET invalidates all tokens simultaneously
 *   - The server never stores the plaintext token
 *
 * !! IMPORTANT: The decrypted token is a credential. Keep it private.
 *    Do not publish it, log it, or share it. It is unique to your beacon_id.
 *    Anyone holding your token can send inbox messages and submit responses
 *    attributed to your beacon_id. Treat it like a private key.
 *
 * Encryption algorithms (auto-detected from node's aether.json):
 *   ML-KEM-768+ChaCha20-Poly1305  — AGS v0.3 (post-quantum)
 *   X25519+ChaCha20-Poly1305      — AGS v0.2 (classical legacy)
 *
 * To use the token after decryption:
 *   Authorization: Bearer {token_hex}
 *   X-Beacon-ID:   {beacon_id}
 * on: POST /respond, POST /inbox/{recipient_beacon_id}
 */

import {
  generateKeyPairSync,
  diffieHellman,
  createPublicKey,
  hkdfSync,
  createCipheriv,
  randomBytes,
  createHash,
} from "node:crypto";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { deriveMeshToken } from "./lib/mesh-auth.mjs";

const TIMEOUT_MS    = 10000;
const GITHUB_TOKEN  = process.env.GITHUB_TOKEN;
const GITHUB_OWNER  = process.env.GITHUB_OWNER;
const GITHUB_REPO   = process.env.GITHUB_REPO;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";

const GH_HEADERS = () => ({
  "Authorization":        `Bearer ${GITHUB_TOKEN}`,
  "Accept":               "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
});

// Fetch a local-hosted manifest from GitHub directly (avoids self-referential HTTP).
// Derives the repo path from the node's URL, so works for both the founding node (/)
// and proxy nodes (/nodes/{beaconId}/).
async function fetchLocalManifest(nodeUrl) {
  const parsed   = new URL(nodeUrl);
  const repoPath = (parsed.pathname.replace(/^\//, "").replace(/\/?$/, "/") + "aether.json").replace(/^\//, "");
  const r = await fetchWithTimeout(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${repoPath}?ref=${GITHUB_BRANCH}`,
    { headers: GH_HEADERS() }
  );
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`GitHub manifest fetch ${r.status} for ${repoPath}`);
  const data = await r.json();
  return JSON.parse(Buffer.from(data.content, "base64").toString("utf-8"));
}

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type":                 "application/json",
};

function reply(statusCode, body) {
  return { statusCode, headers: CORS, body: JSON.stringify(body, null, 2) };
}

async function fetchWithTimeout(url, opts = {}) {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(TIMEOUT_MS) });
}

// ── SSRF guard ────────────────────────────────────────────────────────────────
function validateUrl(urlStr) {
  if (typeof urlStr !== "string" || urlStr.length > 500) return { ok: false };
  let parsed;
  try { parsed = new URL(urlStr); } catch { return { ok: false }; }
  if (parsed.protocol !== "https:") return { ok: false };
  const h = parsed.hostname.toLowerCase();
  const blocked = [
    /^localhost$/, /^0\.0\.0\.0$/, /^127\./, /^10\./,
    /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^169\.254\./,
    /^\[?::1\]?$/, /^\[?fc/, /^\[?fd/,
  ];
  if (blocked.some(p => p.test(h))) return { ok: false };
  if (!h.includes(".")) return { ok: false };
  return { ok: true };
}

// ── ML-KEM-768 encryption (post-quantum) ─────────────────────────────────────
function encryptToMLKEM768(recipientPublicKeyHex, plaintext) {
  const recipientPK = new Uint8Array(Buffer.from(recipientPublicKeyHex, "hex"));
  const { cipherText: ct_kem, sharedSecret: ss } = ml_kem768.encapsulate(recipientPK);
  const nonce = randomBytes(12);
  const k = Buffer.from(hkdfSync("sha3-512", Buffer.from(ss), nonce,
    Buffer.from("AETHER-MESH-TOKEN-v1"), 32));
  const cipher  = createCipheriv("chacha20-poly1305", k, nonce, { authTagLength: 16 });
  const ct_body = cipher.update(Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext));
  cipher.final();
  return {
    algorithm: "ML-KEM-768+ChaCha20-Poly1305",
    ct_kem:    Buffer.from(ct_kem).toString("hex"),
    nonce:     nonce.toString("hex"),
    ct:        Buffer.concat([ct_body, cipher.getAuthTag()]).toString("hex"),
  };
}

// ── X25519 encryption (classical legacy) ─────────────────────────────────────
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function encryptToX25519(recipientPublicKeyHex, plaintext) {
  const { privateKey: e_sk, publicKey: e_pk_obj } = generateKeyPairSync("x25519");
  const e_pk_raw     = e_pk_obj.export({ format: "der", type: "spki" }).slice(12);
  const recipientKey = createPublicKey({
    key:    Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(recipientPublicKeyHex, "hex")]),
    format: "der", type: "spki",
  });
  const ss    = diffieHellman({ privateKey: e_sk, publicKey: recipientKey });
  const nonce = randomBytes(12);
  const k     = Buffer.from(hkdfSync("sha3-512", ss, nonce,
    Buffer.from("AETHER-MESH-TOKEN-v1"), 32));
  const cipher  = createCipheriv("chacha20-poly1305", k, nonce, { authTagLength: 16 });
  const ct_body = cipher.update(Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext));
  cipher.final();
  return {
    algorithm: "X25519+ChaCha20-Poly1305",
    e_pk:      e_pk_raw.toString("hex"),
    nonce:     nonce.toString("hex"),
    ct:        Buffer.concat([ct_body, cipher.getAuthTag()]).toString("hex"),
  };
}

// ── Handler ───────────────────────────────────────────────────────────────────
export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: CORS, body: "" };
  }
  if (event.httpMethod !== "GET") {
    return reply(405, { status: "ERROR", reason: "METHOD_NOT_ALLOWED" });
  }

  const pathParts = (event.path || "").split("/").filter(Boolean);
  const beaconId  = pathParts[pathParts.length - 1];

  if (!beaconId || beaconId === "mesh-token") {
    return reply(400, {
      status:  "ERROR",
      reason:  "MISSING_BEACON_ID",
      message: "Path must be /mesh-token/{beacon_id}",
      example: "/mesh-token/MY-NODE-001",
    });
  }

  if (!/^[A-Za-z0-9_\-]+$/.test(beaconId)) {
    return reply(400, { status: "ERROR", reason: "INVALID_BEACON_ID" });
  }

  // ── Resolve node's encryption key via registry + manifest ─────────────────
  let encryptionPublicKey, encryptionAlgorithm;
  try {
    const regR = await fetchWithTimeout("https://aetherbeacon.io/aether-registry.json");
    if (!regR.ok) throw new Error("registry unavailable");
    const registry = await regR.json();

    const node = registry.nodes?.find(n => n.beacon_id === beaconId);
    if (!node) {
      return reply(404, {
        status:    "NOT_FOUND",
        beacon_id: beaconId,
        message:   "beacon_id not found in AETHER registry. Register first: POST /register or POST /proxy-register",
      });
    }

    // Detect proxy-hosted nodes — their URL is on aetherbeacon.io itself.
    // Netlify functions cannot reliably fetch from their own domain (self-referential HTTP).
    // For proxy nodes, read the manifest from GitHub directly instead.
    let manifest;
    const isProxyNode = (() => {
      try { return new URL(node.url).hostname === "aetherbeacon.io"; } catch { return false; }
    })();

    if (isProxyNode) {
      manifest = await fetchLocalManifest(node.url);
      if (!manifest) {
        return reply(404, {
          status:    "NOT_FOUND",
          beacon_id: beaconId,
          message:   "Manifest not found in repository. Re-register via POST /proxy-register.",
        });
      }
    } else {
      const urlCheck = validateUrl(node.url);
      if (!urlCheck.ok) {
        return reply(400, { status: "ERROR", reason: "INVALID_NODE_URL" });
      }
      const manifestUrl = node.url.endsWith("/")
        ? `${node.url}aether.json`
        : `${node.url}/aether.json`;
      const manifestR = await fetchWithTimeout(manifestUrl);
      if (!manifestR.ok) throw new Error(`manifest fetch HTTP ${manifestR.status}`);
      manifest = await manifestR.json();
    }

    if (!manifest.encryption?.public_key) {
      return reply(422, {
        status:    "NO_ENCRYPTION_KEY",
        beacon_id: beaconId,
        message:   "Node has no encryption.public_key in aether.json. Cannot issue mesh token.",
        hint:      "Add an encryption keypair to your aether.json: python aether_ghost_seal.py keygen-encryption [--pq]",
      });
    }

    encryptionPublicKey = manifest.encryption.public_key;
    encryptionAlgorithm = manifest.encryption.algorithm || "X25519+ChaCha20-Poly1305";
  } catch (e) {
    console.error("[AETHER] mesh-token: node resolution failed:", e.message);
    return reply(502, { status: "ERROR", reason: "NODE_UNREACHABLE" });
  }

  // ── Derive per-node token ─────────────────────────────────────────────────
  let tokenHex;
  try {
    tokenHex = deriveMeshToken(beaconId);
  } catch (e) {
    console.error("[AETHER] mesh-token: token derivation failed:", e.message);
    return reply(500, { status: "ERROR", reason: "TOKEN_DERIVATION_FAILED",
      message: "MESH_TOKEN_SECRET not configured on this server." });
  }

  // ── Encrypt token to node's public key ────────────────────────────────────
  let encrypted;
  try {
    const tokenBuf = Buffer.from(tokenHex, "utf-8"); // encrypt the hex string directly
    if (encryptionAlgorithm === "ML-KEM-768+ChaCha20-Poly1305") {
      encrypted = encryptToMLKEM768(encryptionPublicKey, tokenBuf);
    } else {
      encrypted = encryptToX25519(encryptionPublicKey, tokenBuf);
    }
  } catch (e) {
    console.error("[AETHER] mesh-token: encryption failed:", e.message);
    return reply(500, { status: "ERROR", reason: "ENCRYPTION_FAILED" });
  }

  console.log(`[AETHER] Mesh token issued for ${beaconId} (${encryptionAlgorithm})`);

  const isMLKEM = encryptionAlgorithm === "ML-KEM-768+ChaCha20-Poly1305";
  const encryptedToken = isMLKEM
    ? { ct_kem: encrypted.ct_kem, nonce: encrypted.nonce, ct: encrypted.ct }
    : { e_pk: encrypted.e_pk, nonce: encrypted.nonce, ct: encrypted.ct };

  const decryptSteps = isMLKEM
    ? [
        "1. ss = ml_kem768.decapsulate(ct_kem, your_secret_key)",
        "2. k  = HKDF-SHA3-512(ikm=ss, salt=nonce, info='AETHER-MESH-TOKEN-v1')",
        "3. token_hex = ChaCha20-Poly1305.decrypt(k, nonce, ct[:-16], tag=ct[-16:])",
        "4. Decode token_hex as UTF-8 string — this is your 64-char hex bearer token",
      ]
    : [
        "1. ss = X25519(your_private_key, e_pk)",
        "2. k  = HKDF-SHA3-512(ikm=ss, salt=nonce, info='AETHER-MESH-TOKEN-v1')",
        "3. token_hex = ChaCha20-Poly1305.decrypt(k, nonce, ct[:-16], tag=ct[-16:])",
        "4. Decode token_hex as UTF-8 string — this is your 64-char hex bearer token",
      ];

  return reply(200, {
    status:       "TOKEN_ISSUED",
    beacon_id:    beaconId,
    algorithm:    encryptionAlgorithm,
    info_string:  "AETHER-MESH-TOKEN-v1",
    encrypted_token: encryptedToken,
    decrypt_steps: decryptSteps,
    usage: {
      description: "Include these headers on POST /respond and POST /inbox/{recipient}",
      headers: {
        "Authorization": "Bearer {decrypted_token_hex}",
        "X-Beacon-ID":   beaconId,
      },
    },
    security_notice: [
      "!! The decrypted token is a credential unique to your beacon_id.",
      "!! Keep it private. Do not publish, log, or share it.",
      "!! Anyone holding your token can send messages and submit responses attributed to your beacon_id.",
      "!! If your token is compromised, contact the operator to rotate MESH_TOKEN_SECRET.",
      "!! Treat this token with the same care as your private encryption key.",
    ],
  });
};
