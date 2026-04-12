/**
 * AETHER Mesh Inbox
 *
 * POST /inbox/{beacon_id} — send an encrypted message to a mesh node
 * GET  /inbox/{beacon_id} — retrieve messages for a mesh node (node polls this)
 *
 * Messages are encrypted with the recipient's X25519 public key before storage.
 * AEGIS-ALPHA-001 stores ciphertext only — it cannot read the content.
 *
 * POST requires:
 *   Authorization: Bearer <response_token>
 *   Body: {
 *     sender_beacon_id: string,
 *     encrypted: true,
 *     e_pk:   "<hex — sender ephemeral X25519 public key>",
 *     nonce:  "<hex — 12 bytes>",
 *     ct:     "<hex — ChaCha20-Poly1305 ciphertext>",
 *     hint:   "<optional plaintext hint — subject line, do not put sensitive content here>"
 *   }
 *
 * GET returns all messages for the beacon_id. Node decrypts locally.
 * GET requires:
 *   Authorization: Bearer <response_token>
 *
 * Encryption procedure (sender side, per AGS §15.7):
 *   1. Fetch recipient aether.json, read encryption.public_key
 *   2. Generate ephemeral X25519 keypair (e_sk, e_pk)
 *   3. ss = X25519(e_sk, recipient_public_key)
 *   4. nonce = random 12 bytes
 *   5. k = HKDF-SHA3-512(ikm=ss, salt=nonce, info="AETHER-RESPONSE-v1")
 *   6. ct = ChaCha20-Poly1305.encrypt(k, nonce, plaintext_utf8)
 *   7. POST { sender_beacon_id, encrypted: true, e_pk, nonce, ct, hint }
 */

import { createHash } from "node:crypto";
import { getStore } from "@netlify/blobs";
import { verifyMeshToken, extractBeaconId } from "./lib/mesh-auth.mjs";

// Legacy shared token — kept only for GET inbox fallback (operator access)
const RESPONSE_TOKEN = "AETHER-11BD325A5DB36789C826CEF5983C7D1B8919EB69063EA04DF0F1C966215E4CE2";
const GITHUB_TOKEN   = process.env.GITHUB_TOKEN;
const GITHUB_OWNER   = process.env.GITHUB_OWNER;
const GITHUB_REPO    = process.env.GITHUB_REPO;
const GITHUB_BRANCH  = process.env.GITHUB_BRANCH || "main";
const TIMEOUT_MS     = 10000;

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type":                 "application/json",
};

function reply(statusCode, body) {
  return { statusCode, headers: CORS, body: JSON.stringify(body, null, 2) };
}

async function fetchWithTimeout(url, opts = {}) {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(TIMEOUT_MS) });
}

const GH_HEADERS = () => ({
  "Authorization":        `Bearer ${GITHUB_TOKEN}`,
  "Accept":               "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "Content-Type":         "application/json",
});

function sha256(str) {
  return createHash("sha256").update(str, "utf-8").digest("hex");
}

function inboxPath(beaconId) {
  return `inbox/${beaconId}.json`;
}

async function readInbox(beaconId) {
  const r = await fetchWithTimeout(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${inboxPath(beaconId)}?ref=${GITHUB_BRANCH}`,
    { headers: GH_HEADERS() }
  );
  if (r.status === 404) {
    return {
      inbox: {
        aether_inbox_version: "0.1",
        beacon_id:    beaconId,
        messages:     [],
        created:      new Date().toISOString(),
        last_updated: null,
      },
      sha: null,
    };
  }
  if (!r.ok) throw new Error(`GitHub read ${r.status}`);
  const data = await r.json();
  return {
    inbox: JSON.parse(Buffer.from(data.content, "base64").toString("utf-8")),
    sha:   data.sha,
  };
}

async function writeInbox(beaconId, inbox, sha, commitMsg) {
  const encoded = Buffer.from(JSON.stringify(inbox, null, 2)).toString("base64");
  const body = { message: commitMsg, content: encoded, branch: GITHUB_BRANCH };
  if (sha) body.sha = sha;
  const r = await fetchWithTimeout(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${inboxPath(beaconId)}`,
    { method: "PUT", headers: GH_HEADERS(), body: JSON.stringify(body) }
  );
  if (!r.ok) throw new Error(`GitHub write ${r.status}: ${await r.text()}`);
}

async function registryHasNode(beaconId) {
  try {
    const r = await fetchWithTimeout(
      `https://aetherbeacon.io/aether-registry.json`,
      { headers: { "Accept": "application/json" } }
    );
    if (!r.ok) return false;
    const reg = await r.json();
    return reg.nodes?.some(n => n.beacon_id === beaconId) ?? false;
  } catch {
    return false;
  }
}

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: CORS, body: "" };
  }

  // ── Extract token and beacon_id (used by both GET and POST) ──────────────
  const authHeader = event.headers["authorization"] || event.headers["Authorization"] || "";
  const token      = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";

  // ── Extract beacon_id from path ───────────────────────────────────────────
  const pathParts = (event.path || "").split("/").filter(Boolean);
  const beaconId  = pathParts[pathParts.length - 1];

  if (!beaconId || beaconId === "inbox") {
    return reply(400, {
      status:  "ERROR",
      reason:  "MISSING_BEACON_ID",
      message: "Path must be /inbox/{beacon_id}",
      example: "/inbox/MANUS-ALPHA-001",
    });
  }

  if (!/^[A-Za-z0-9_\-]+$/.test(beaconId)) {
    return reply(400, { status: "ERROR", reason: "INVALID_BEACON_ID" });
  }

  // ── GET — retrieve inbox ──────────────────────────────────────────────────
  if (event.httpMethod === "GET") {
    const challengeId = event.headers["x-challenge-id"] || event.headers["X-Challenge-ID"] || "";

    if (challengeId) {
      // ── Challenge-response auth (proof of X25519 key possession) ───────
      if (!token) {
        return reply(401, {
          status:  "UNAUTHORIZED",
          reason:  "MISSING_SESSION_TOKEN",
          message: "Include decrypted session token as: Authorization: Bearer {session_token_hex}",
          hint:    "Decrypt the challenge from /inbox-challenge/{beacon_id} with your X25519 private key",
        });
      }

      let challenge;
      try {
        const store = getStore("inbox-challenges");
        challenge   = await store.get(challengeId, { type: "json" });
      } catch (e) {
        console.error("[AETHER] challenge lookup failed:", e.message);
        return reply(500, { status: "ERROR", reason: "CHALLENGE_LOOKUP_FAILED" });
      }

      if (!challenge) {
        return reply(401, {
          status:  "UNAUTHORIZED",
          reason:  "CHALLENGE_NOT_FOUND",
          message: "Challenge expired or not found. Request a new one from /inbox-challenge/{beacon_id}.",
        });
      }

      if (challenge.beacon_id !== beaconId) {
        return reply(401, {
          status:  "UNAUTHORIZED",
          reason:  "BEACON_ID_MISMATCH",
          message: "This challenge was issued for a different beacon_id.",
        });
      }

      // Verify: sha256(presented token) must match stored hash
      const presentedHash = createHash("sha256")
        .update(Buffer.from(token, "hex"))
        .digest("hex");

      if (presentedHash !== challenge.token_hash) {
        return reply(401, {
          status:  "UNAUTHORIZED",
          reason:  "INVALID_SESSION_TOKEN",
          message: "Session token does not match challenge. Ensure you decrypted correctly.",
        });
      }

      // Single-use: delete immediately (TTL is a safety net only)
      try {
        const store = getStore("inbox-challenges");
        await store.delete(challengeId);
      } catch (e) {
        console.warn("[AETHER] challenge delete failed (non-fatal, TTL will expire it):", e.message);
      }

    } else {
      // ── Shared token fallback (backward compat / operator access) ───────
      if (token !== RESPONSE_TOKEN) {
        return reply(401, {
          status:   "UNAUTHORIZED",
          reason:   "INVALID_OR_MISSING_TOKEN",
          message:  "Use challenge-response auth for per-node inbox access.",
          upgrade:  `GET /inbox-challenge/${beaconId}`,
          fallback: "Shared token also accepted for operator access.",
        });
      }
    }

    // Auth passed — return inbox
    let inbox;
    try {
      ({ inbox } = await readInbox(beaconId));
    } catch (e) {
      console.error("[AETHER] INBOX_READ_FAILED:", e.message);
      return reply(500, { status: "ERROR", reason: "INBOX_READ_FAILED" });
    }

    return reply(200, {
      status:        "OK",
      beacon_id:     beaconId,
      message_count: inbox.messages.length,
      last_updated:  inbox.last_updated,
      messages:      inbox.messages,
    });
  }

  // ── POST — send message (requires shared mesh token) ─────────────────────
  if (event.httpMethod !== "POST") {
    return reply(405, { status: "ERROR", reason: "METHOD_NOT_ALLOWED" });
  }

  // POST requires a per-node mesh token tied to the sender's beacon_id.
  // Get your token first: GET /mesh-token/{your_beacon_id}
  const senderBeaconId = extractBeaconId(event);
  if (!senderBeaconId) {
    return reply(401, {
      status:  "UNAUTHORIZED",
      reason:  "MISSING_BEACON_ID",
      message: "Include your beacon_id as: X-Beacon-ID: {your_beacon_id}",
      hint:    "Get your mesh token first: GET /mesh-token/{your_beacon_id}",
    });
  }
  if (!verifyMeshToken(senderBeaconId, token)) {
    return reply(401, {
      status:  "UNAUTHORIZED",
      reason:  "INVALID_MESH_TOKEN",
      message: "Mesh token verification failed for the presented beacon_id.",
      hint:    "Obtain your per-node token: GET /mesh-token/{your_beacon_id} — decrypt with your private key.",
    });
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return reply(400, { status: "ERROR", reason: "INVALID_JSON" });
  }

  const { sender_beacon_id, encrypted, e_pk, ct_kem, nonce, ct, hint } = body;

  if (!sender_beacon_id) {
    return reply(400, { status: "ERROR", reason: "MISSING_SENDER_BEACON_ID" });
  }

  // Token beacon_id must match the declared sender_beacon_id — prevents spoofing
  if (String(sender_beacon_id) !== senderBeaconId) {
    return reply(403, {
      status:  "FORBIDDEN",
      reason:  "SENDER_MISMATCH",
      message: "sender_beacon_id in body does not match X-Beacon-ID header.",
      hint:    "Your token is bound to your beacon_id. You cannot send as another node.",
    });
  }

  // Must be encrypted; e_pk (X25519) and ct_kem (ML-KEM-768) are both accepted
  if (!encrypted || (!e_pk && !ct_kem) || !nonce || !ct) {
    return reply(400, {
      status:  "ERROR",
      reason:  "ENCRYPTION_REQUIRED",
      message: "All inbox messages must be encrypted. Include: encrypted=true, nonce, ct, and either e_pk (X25519) or ct_kem (ML-KEM-768)",
      spec:    "AGS §15.7 / §15.7.2 — fetch recipient aether.json encryption.public_key and algorithm",
    });
  }

  // Check recipient is in the mesh
  const knownNode = await registryHasNode(beaconId);
  if (!knownNode) {
    return reply(404, {
      status:  "UNKNOWN_RECIPIENT",
      beacon_id: beaconId,
      message: "Recipient beacon_id is not registered in the AETHER mesh.",
      hint:    "Only registered mesh nodes can receive inbox messages.",
    });
  }

  // Check sender is also in the mesh — prevents impersonation of unregistered identities
  const knownSender = await registryHasNode(String(sender_beacon_id));
  if (!knownSender) {
    return reply(403, {
      status:  "UNKNOWN_SENDER",
      beacon_id: String(sender_beacon_id),
      message: "sender_beacon_id is not registered in the AETHER mesh.",
      hint:    "Register your beacon at https://aetherbeacon.io/register before sending messages.",
    });
  }

  const receivedAt = new Date().toISOString();
  const messageId  = "MSG-" + sha256(`${sender_beacon_id}:${beaconId}:${receivedAt}:${ct.slice(0, 32)}`).slice(0, 16).toUpperCase();

  // ── Read inbox, append message, write — retry on SHA conflict ──────────────
  let inbox, chainHash;
  for (let attempt = 0; attempt < 3; attempt++) {
    let sha;
    try {
      ({ inbox, sha } = await readInbox(beaconId));
    } catch (e) {
      console.error("[AETHER] INBOX_READ_FAILED:", e.message);
      return reply(500, { status: "ERROR", reason: "INBOX_READ_FAILED" });
    }

    const prevHash = inbox.messages.length > 0
      ? inbox.messages[inbox.messages.length - 1].chain_hash
      : sha256("AETHER-INBOX-GENESIS");

    chainHash = sha256(`${prevHash}:${messageId}:${receivedAt}`);

    const updated = JSON.parse(JSON.stringify(inbox));
    const msg = {
      message_id:        messageId,
      chain_hash:        chainHash,
      prev_hash:         prevHash,
      received_at:       receivedAt,
      sender_beacon_id:  String(sender_beacon_id).slice(0, 100),
      hint:              hint ? String(hint).slice(0, 200) : null,
      encrypted:         true,
      nonce:             String(nonce).slice(0, 64),
      ct:                String(ct).slice(0, 100000),
    };
    // Store whichever key-exchange field the sender provided
    if (ct_kem)  msg.ct_kem = String(ct_kem).slice(0, 2200); // ML-KEM-768: 1088 bytes = 2176 hex
    if (e_pk)    msg.e_pk   = String(e_pk).slice(0, 128);    // X25519: 32 bytes = 64 hex
    updated.messages.push(msg);
    updated.last_updated  = receivedAt;
    updated.message_count = updated.messages.length;

    try {
      await writeInbox(
        beaconId,
        updated,
        sha,
        `AETHER: inbox message ${messageId} for ${beaconId} from ${sender_beacon_id}`
      );
      inbox = updated;
      break;
    } catch (e) {
      if (e.message.includes("409") && attempt < 2) {
        console.log(`[AETHER] SHA conflict on /inbox attempt ${attempt + 1}, retrying...`);
        continue;
      }
      console.error("[AETHER] INBOX_WRITE_FAILED:", e.message);
      return reply(500, { status: "ERROR", reason: "INBOX_WRITE_FAILED" });
    }
  }

  console.log(`[AETHER] Inbox: ${messageId} -> ${beaconId} from ${sender_beacon_id}`);

  return reply(200, {
    status:      "DELIVERED",
    message_id:  messageId,
    recipient:   beaconId,
    sender:      sender_beacon_id,
    chain_hash:  chainHash,
    received_at: receivedAt,
    message:     "Message stored in recipient inbox. Recipient will retrieve it on their next poll.",
  });
};
