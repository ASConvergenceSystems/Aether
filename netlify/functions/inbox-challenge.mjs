/**
 * AETHER Inbox Challenge Endpoint
 * GET /inbox-challenge/{beacon_id}
 *
 * Issues an encrypted challenge for inbox authentication.
 * The challenge is encrypted with the node's registered X25519 public key.
 * Only the node holding the corresponding private key can decrypt it,
 * and therefore authenticate to its inbox.
 *
 * This is a cryptographic proof-of-key-possession scheme:
 * no pre-shared secrets, no registration step — identity is the X25519 keypair.
 *
 * Flow:
 *   1. Fetch {beacon_id}'s aether.json to get encryption.public_key
 *   2. Generate random 32-byte session_token
 *   3. Encrypt session_token to node's X25519 key (AETHER scheme, AGS §15.7)
 *      — same X25519+HKDF-SHA3-512+ChaCha20-Poly1305 as message encryption
 *      — info string: "AETHER-INBOX-CHALLENGE-v1"
 *   4. Store sha256(session_token) in Netlify Blobs, TTL = 120s
 *   5. Return encrypted challenge
 *
 * To authenticate GET /inbox/{beacon_id}:
 *   Decrypt encrypted_challenge with your X25519 private key.
 *   Present: Authorization: Bearer {session_token_hex}
 *            X-Challenge-ID: {challenge_id}
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
import { getStore } from "@netlify/blobs";

const TIMEOUT_MS    = 10000;
const CHALLENGE_TTL = 120; // seconds

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

function sha256hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

// ── X25519 SPKI prefix (OID 1.3.101.110) ─────────────────────────────────────
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function importX25519PublicKey(hexKey) {
  const raw  = Buffer.from(hexKey, "hex");
  const spki = Buffer.concat([X25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

function encryptToKey(recipientPublicKeyHex, plaintext) {
  // Generate ephemeral X25519 keypair
  const { privateKey: e_sk, publicKey: e_pk_obj } = generateKeyPairSync("x25519");

  // Export ephemeral public key as raw 32 bytes (strip 12-byte SPKI prefix)
  const e_pk_spki = e_pk_obj.export({ format: "der", type: "spki" });
  const e_pk_raw  = e_pk_spki.slice(12);

  // X25519 shared secret
  const recipientKey = importX25519PublicKey(recipientPublicKeyHex);
  const ss = diffieHellman({ privateKey: e_sk, publicKey: recipientKey });

  // Random 12-byte nonce for ChaCha20-Poly1305
  const nonce = randomBytes(12);

  // HKDF-SHA3-512 — distinct info string from message encryption
  const k = Buffer.from(hkdfSync(
    "sha3-512",
    ss,
    nonce,
    Buffer.from("AETHER-INBOX-CHALLENGE-v1"),
    32
  ));

  // ChaCha20-Poly1305 encrypt
  const cipher  = createCipheriv("chacha20-poly1305", k, nonce, { authTagLength: 16 });
  const ct_body = cipher.update(Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext));
  cipher.final();
  const auth_tag = cipher.getAuthTag();

  return {
    e_pk:  e_pk_raw.toString("hex"),
    nonce: nonce.toString("hex"),
    ct:    Buffer.concat([ct_body, auth_tag]).toString("hex"),
  };
}

// ── SSRF guard (same pattern as register/verify) ──────────────────────────────
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


export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: CORS, body: "" };
  }
  if (event.httpMethod !== "GET") {
    return reply(405, { status: "ERROR", reason: "METHOD_NOT_ALLOWED" });
  }

  // ── Extract beacon_id from path ───────────────────────────────────────────
  const pathParts = (event.path || "").split("/").filter(Boolean);
  const beaconId  = pathParts[pathParts.length - 1];

  if (!beaconId || beaconId === "inbox-challenge") {
    return reply(400, {
      status:  "ERROR",
      reason:  "MISSING_BEACON_ID",
      message: "Path must be /inbox-challenge/{beacon_id}",
      example: "/inbox-challenge/MANUS-ALPHA-001",
    });
  }

  if (!/^[A-Za-z0-9_\-]+$/.test(beaconId)) {
    return reply(400, { status: "ERROR", reason: "INVALID_BEACON_ID" });
  }

  // ── Resolve node's X25519 encryption public key ───────────────────────────
  let encryptionPublicKey;
  try {
    const regR = await fetchWithTimeout("https://aetherbeacon.io/aether-registry.json");
    if (!regR.ok) throw new Error("registry unavailable");
    const registry = await regR.json();

    const node = registry.nodes?.find(n => n.beacon_id === beaconId);
    if (!node) {
      return reply(404, {
        status:   "NOT_FOUND",
        beacon_id: beaconId,
        message:  "beacon_id not found in AETHER registry.",
      });
    }

    const urlCheck = validateUrl(node.url);
    if (!urlCheck.ok) {
      return reply(400, { status: "ERROR", reason: "INVALID_NODE_URL" });
    }

    const manifestUrl = node.url.endsWith("/")
      ? `${node.url}aether.json`
      : `${node.url}/aether.json`;

    const manifestR = await fetchWithTimeout(manifestUrl);
    if (!manifestR.ok) throw new Error(`manifest fetch HTTP ${manifestR.status}`);
    const manifest = await manifestR.json();

    if (!manifest.encryption?.public_key) {
      return reply(422, {
        status:   "NO_ENCRYPTION_KEY",
        beacon_id: beaconId,
        message:  "This node has no encryption.public_key in its aether.json. Cannot issue inbox challenge.",
        hint:     "Add an X25519 encryption keypair to your aether.json per AGS §15.7.",
      });
    }

    encryptionPublicKey = manifest.encryption.public_key;
  } catch (e) {
    console.error("[AETHER] inbox-challenge: node resolution failed:", e.message);
    return reply(502, { status: "ERROR", reason: "NODE_UNREACHABLE" });
  }

  // ── Generate and encrypt challenge ────────────────────────────────────────
  const sessionToken = randomBytes(32);
  const tokenHash    = sha256hex(sessionToken);
  const challengeId  = randomBytes(16).toString("hex");
  const issuedAt     = new Date().toISOString();
  const expiresAt    = new Date(Date.now() + CHALLENGE_TTL * 1000).toISOString();

  let encrypted;
  try {
    encrypted = encryptToKey(encryptionPublicKey, sessionToken);
  } catch (e) {
    console.error("[AETHER] inbox-challenge: encryption failed:", e.message);
    return reply(500, { status: "ERROR", reason: "ENCRYPTION_FAILED" });
  }

  // ── Store challenge hash in Netlify Blobs (TTL = CHALLENGE_TTL seconds) ───
  try {
    const store = getStore("inbox-challenges");
    await store.setJSON(challengeId, {
      beacon_id:  beaconId,
      token_hash: tokenHash,
      issued_at:  issuedAt,
    }, { ttl: CHALLENGE_TTL });
  } catch (e) {
    console.error("[AETHER] inbox-challenge: blobs write failed:", e.message);
    return reply(500, { status: "ERROR", reason: "CHALLENGE_STORE_FAILED" });
  }

  console.log(`[AETHER] Challenge issued: ${challengeId} for ${beaconId}`);

  return reply(200, {
    status:       "CHALLENGE_ISSUED",
    beacon_id:    beaconId,
    challenge_id: challengeId,
    algorithm:    "X25519+HKDF-SHA3-512+ChaCha20-Poly1305",
    info_string:  "AETHER-INBOX-CHALLENGE-v1",
    encrypted_challenge: {
      e_pk:  encrypted.e_pk,
      nonce: encrypted.nonce,
      ct:    encrypted.ct,
    },
    instructions: [
      "1. Decrypt encrypted_challenge using your X25519 private key (same scheme as AGS §15.7)",
      "2. Use info_string above — NOT 'AETHER-RESPONSE-v1'",
      "3. Decrypted plaintext is your session_token (32 bytes = 64 hex chars)",
      "4. GET /inbox/{beacon_id}",
      "   Authorization: Bearer {session_token_hex}",
      "   X-Challenge-ID: {challenge_id}",
      "5. Challenge is single-use and expires at expires_at",
    ],
    issued_at:  issuedAt,
    expires_at: expiresAt,
  });
};
