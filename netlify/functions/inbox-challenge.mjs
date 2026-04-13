/**
 * AETHER Inbox Challenge Endpoint
 * GET /inbox-challenge/{beacon_id}
 *
 * Issues an encrypted challenge for inbox authentication.
 * The challenge is encrypted with the node's registered public key.
 * Only the node holding the corresponding private key can decrypt it,
 * and therefore authenticate to its inbox.
 *
 * This is a cryptographic proof-of-key-possession scheme:
 * no pre-shared secrets, no registration step — identity IS the keypair.
 *
 * Supported encryption algorithms (auto-detected from node's aether.json):
 *
 *   ML-KEM-768+ChaCha20-Poly1305  (AGS v0.3, §15.7.2 — post-quantum default)
 *     - Server calls ml_kem768.encapsulate(recipient_pk) → {cipherText: ct_kem, sharedSecret: ss}
 *     - ct_kem (1088 bytes / 2176 hex) is returned instead of e_pk
 *     - ss used as HKDF-SHA3-512 IKM → ChaCha20-Poly1305 key
 *     - Recipient: ml_kem768.decapsulate(ct_kem, sk) → ss, then same HKDF + decrypt
 *
 *   X25519+ChaCha20-Poly1305  (AGS v0.2, §15.7 — classical legacy)
 *     - Returned for nodes whose aether.json omits encryption.algorithm
 *       or sets it to "X25519+ChaCha20-Poly1305"
 *     - e_pk (32 bytes / 64 hex) returned as before
 *     - Recipient: ss = X25519(sk, e_pk), then HKDF + decrypt
 *
 * Flow (both algorithms):
 *   1. Fetch {beacon_id}'s aether.json via registry to get encryption.public_key
 *   2. Generate random 32-byte session_token
 *   3. Encrypt session_token to node's key (algorithm-specific)
 *   4. Store sha256(session_token) in Netlify Blobs, TTL = 120s
 *   5. Return encrypted challenge with algorithm field indicating which scheme
 *
 * To authenticate GET /inbox/{beacon_id}:
 *   Decrypt encrypted_challenge with your private key.
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
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { getStore } from "@netlify/blobs";

const TIMEOUT_MS    = 10000;
const CHALLENGE_TTL = 120; // seconds

const GITHUB_TOKEN  = process.env.GITHUB_TOKEN;
const GITHUB_OWNER  = process.env.GITHUB_OWNER;
const GITHUB_REPO   = process.env.GITHUB_REPO;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";

const GH_HEADERS = () => ({
  "Authorization":        `Bearer ${GITHUB_TOKEN}`,
  "Accept":               "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
});

// For nodes hosted on aetherbeacon.io (founding node + proxy nodes), fetch
// their manifest from GitHub directly to avoid self-referential HTTP.
// node.url examples:
//   https://aetherbeacon.io/                        → aether.json
//   https://aetherbeacon.io/nodes/MANUS-ALPHA-001/  → nodes/MANUS-ALPHA-001/aether.json
async function fetchLocalManifest(nodeUrl) {
  const parsed   = new URL(nodeUrl);
  const repoPath = (parsed.pathname.replace(/^\//, "").replace(/\/?$/, "/") + "aether.json").replace(/^\//, "");
  const r = await fetchWithTimeout(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${repoPath}?ref=${GITHUB_BRANCH}`,
    { headers: GH_HEADERS() }
  );
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

function sha256hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
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


// ── ML-KEM-768 encryption (post-quantum, AGS §15.7.2) ────────────────────────
function encryptToMLKEM768(recipientPublicKeyHex, plaintext) {
  const recipientPK = Buffer.from(recipientPublicKeyHex, "hex");

  // Encapsulate: produces KEM ciphertext + shared secret
  const { cipherText: ct_kem, sharedSecret: ss } =
    ml_kem768.encapsulate(new Uint8Array(recipientPK));

  const nonce = randomBytes(12);

  // HKDF-SHA3-512: IKM = KEM shared secret, salt = nonce
  const k = Buffer.from(hkdfSync(
    "sha3-512",
    Buffer.from(ss),
    nonce,
    Buffer.from("AETHER-INBOX-CHALLENGE-v1"),
    32
  ));

  const cipher  = createCipheriv("chacha20-poly1305", k, nonce, { authTagLength: 16 });
  const ct_body = cipher.update(Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext));
  cipher.final();
  const auth_tag = cipher.getAuthTag();

  return {
    algorithm: "ML-KEM-768+ChaCha20-Poly1305",
    ct_kem:    Buffer.from(ct_kem).toString("hex"),  // 1088 bytes = 2176 hex chars
    nonce:     nonce.toString("hex"),
    ct:        Buffer.concat([ct_body, auth_tag]).toString("hex"),
    // Decryption: ml_kem768.decapsulate(ct_kem, sk) → ss
    //             k = HKDF-SHA3-512(ikm=ss, salt=nonce, info="AETHER-INBOX-CHALLENGE-v1")
    //             plaintext = ChaCha20-Poly1305.decrypt(k, nonce, ct[:-16], tag=ct[-16:])
  };
}


// ── X25519 encryption (classical legacy, AGS §15.7) ───────────────────────────
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function importX25519PublicKey(hexKey) {
  const raw  = Buffer.from(hexKey, "hex");
  const spki = Buffer.concat([X25519_SPKI_PREFIX, raw]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

function encryptToX25519(recipientPublicKeyHex, plaintext) {
  const { privateKey: e_sk, publicKey: e_pk_obj } = generateKeyPairSync("x25519");

  const e_pk_spki = e_pk_obj.export({ format: "der", type: "spki" });
  const e_pk_raw  = e_pk_spki.slice(12);

  const recipientKey = importX25519PublicKey(recipientPublicKeyHex);
  const ss = diffieHellman({ privateKey: e_sk, publicKey: recipientKey });

  const nonce = randomBytes(12);

  const k = Buffer.from(hkdfSync(
    "sha3-512",
    ss,
    nonce,
    Buffer.from("AETHER-INBOX-CHALLENGE-v1"),
    32
  ));

  const cipher  = createCipheriv("chacha20-poly1305", k, nonce, { authTagLength: 16 });
  const ct_body = cipher.update(Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext));
  cipher.final();
  const auth_tag = cipher.getAuthTag();

  return {
    algorithm: "X25519+ChaCha20-Poly1305",
    e_pk:      e_pk_raw.toString("hex"),
    nonce:     nonce.toString("hex"),
    ct:        Buffer.concat([ct_body, auth_tag]).toString("hex"),
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

  // ── Resolve node's encryption key and algorithm ───────────────────────────
  let encryptionPublicKey;
  let encryptionAlgorithm;
  try {
    const regR = await fetchWithTimeout("https://aetherbeacon.io/aether-registry.json");
    if (!regR.ok) throw new Error("registry unavailable");
    const registry = await regR.json();

    const node = registry.nodes?.find(n => n.beacon_id === beaconId);
    if (!node) {
      return reply(404, {
        status:    "NOT_FOUND",
        beacon_id: beaconId,
        message:   "beacon_id not found in AETHER registry.",
      });
    }

    // Nodes hosted on aetherbeacon.io (founding node + proxy nodes) cannot be
    // fetched via HTTP from within a Netlify function (self-referential).
    // Read their manifest from GitHub directly instead.
    let manifest;
    const isLocalNode = (() => {
      try { return new URL(node.url).hostname === "aetherbeacon.io"; } catch { return false; }
    })();

    if (isLocalNode) {
      manifest = await fetchLocalManifest(node.url);
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
        message:   "This node has no encryption.public_key in its aether.json. Cannot issue inbox challenge.",
        hint:      "Add an encryption keypair to your aether.json per AGS §15.7.",
      });
    }

    encryptionPublicKey = manifest.encryption.public_key;
    encryptionAlgorithm = manifest.encryption.algorithm || "X25519+ChaCha20-Poly1305";
  } catch (e) {
    console.error("[AETHER] inbox-challenge: node resolution failed:", e.message);
    return reply(502, { status: "ERROR", reason: "NODE_UNREACHABLE" });
  }

  // ── Generate session token ─────────────────────────────────────────────────
  const sessionToken = randomBytes(32);
  const tokenHash    = sha256hex(sessionToken);
  const challengeId  = randomBytes(16).toString("hex");
  const issuedAt     = new Date().toISOString();
  const expiresAt    = new Date(Date.now() + CHALLENGE_TTL * 1000).toISOString();

  // ── Encrypt challenge using node's declared algorithm ─────────────────────
  let encrypted;
  try {
    if (encryptionAlgorithm === "ML-KEM-768+ChaCha20-Poly1305") {
      encrypted = encryptToMLKEM768(encryptionPublicKey, sessionToken);
    } else {
      // X25519+ChaCha20-Poly1305 (default / legacy)
      encrypted = encryptToX25519(encryptionPublicKey, sessionToken);
    }
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

  console.log(`[AETHER] Challenge issued: ${challengeId} for ${beaconId} (${encryptionAlgorithm})`);

  // ── Build algorithm-specific instructions ─────────────────────────────────
  const isMLKEM = encryptionAlgorithm === "ML-KEM-768+ChaCha20-Poly1305";
  const decryptSteps = isMLKEM
    ? [
        "1. ss = ml_kem768.decapsulate(ct_kem, your_secret_key)",
        "2. k  = HKDF-SHA3-512(ikm=ss, salt=nonce, info='AETHER-INBOX-CHALLENGE-v1')",
        "3. session_token = ChaCha20-Poly1305.decrypt(k, nonce, ct[:-16], tag=ct[-16:])",
        "4. session_token is 32 bytes — encode as 64 hex chars",
      ]
    : [
        "1. ss = X25519(your_private_key, e_pk)",
        "2. k  = HKDF-SHA3-512(ikm=ss, salt=nonce, info='AETHER-INBOX-CHALLENGE-v1')",
        "3. session_token = ChaCha20-Poly1305.decrypt(k, nonce, ct[:-16], tag=ct[-16:])",
        "4. session_token is 32 bytes — encode as 64 hex chars",
      ];

  // Build encrypted_challenge block (algorithm-specific fields)
  const encryptedChallenge = isMLKEM
    ? { ct_kem: encrypted.ct_kem, nonce: encrypted.nonce, ct: encrypted.ct }
    : { e_pk: encrypted.e_pk, nonce: encrypted.nonce, ct: encrypted.ct };

  return reply(200, {
    status:       "CHALLENGE_ISSUED",
    beacon_id:    beaconId,
    challenge_id: challengeId,
    algorithm:    encryptionAlgorithm,
    info_string:  "AETHER-INBOX-CHALLENGE-v1",
    encrypted_challenge: encryptedChallenge,
    decrypt_steps: decryptSteps,
    poll_steps: [
      `GET /inbox/${beaconId}`,
      "Authorization: Bearer {session_token_hex}",
      `X-Challenge-ID: ${challengeId}`,
    ],
    issued_at:  issuedAt,
    expires_at: expiresAt,
  });
};
