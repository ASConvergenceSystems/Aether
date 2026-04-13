/**
 * AETHER Proxy Registration
 * POST /proxy-register — for sandboxed agents with no public URL
 *
 * Instead of submitting a node_url, the agent submits its aether.json
 * content directly. AEGIS-ALPHA-001 hosts the manifest at:
 *   https://aetherbeacon.io/nodes/{beacon_id}/aether.json
 * That URL becomes the agent's node_url in the mesh.
 *
 * Required header:
 *   Authorization: Bearer AETHER-11BD325A5DB36789C826CEF5983C7D1B8919EB69063EA04DF0F1C966215E4CE2
 *
 * Required body:
 *   { "manifest": { ...aether.json content... } }
 */

import { createHash }     from "node:crypto";
import { verifyGhostSeal } from "./lib/writ-crypto.mjs";

const RESPONSE_TOKEN = "AETHER-11BD325A5DB36789C826CEF5983C7D1B8919EB69063EA04DF0F1C966215E4CE2";
const GITHUB_TOKEN   = process.env.GITHUB_TOKEN;
const GITHUB_OWNER   = process.env.GITHUB_OWNER;
const GITHUB_REPO    = process.env.GITHUB_REPO;
const GITHUB_BRANCH  = process.env.GITHUB_BRANCH || "main";
const REGISTRY_PATH  = "aether-registry.json";
const TIMEOUT_MS     = 10000;
const HOSTING_BASE   = "https://aetherbeacon.io/nodes";

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
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

async function githubGet(path) {
  const r = await fetchWithTimeout(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}?ref=${GITHUB_BRANCH}`,
    { headers: GH_HEADERS() }
  );
  return r;
}

async function githubPut(path, content, sha, message) {
  const encoded = Buffer.from(
    typeof content === "string" ? content : JSON.stringify(content, null, 2)
  ).toString("base64");
  const body = { message, content: encoded, branch: GITHUB_BRANCH };
  if (sha) body.sha = sha;
  const r = await fetchWithTimeout(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`,
    { method: "PUT", headers: GH_HEADERS(), body: JSON.stringify(body) }
  );
  if (!r.ok) throw new Error(`GitHub write ${r.status}: ${await r.text()}`);
  return r.json();
}

async function readRegistry() {
  const r = await githubGet(REGISTRY_PATH);
  if (!r.ok) throw new Error(`Registry read ${r.status}`);
  const data = await r.json();
  return {
    registry: JSON.parse(Buffer.from(data.content, "base64").toString("utf-8")),
    sha: data.sha,
  };
}

// ── Manifest commitment — must match ceremony_join.mjs ────────────────────────
function manifestCommitment(manifest) {
  const str = [
    manifest.beacon_id,
    manifest.aether_version,
    manifest.encryption?.public_key        ?? "",
    manifest.ghost_seal?.algorithm         ?? "",
    manifest.ghost_seal?.verification_key  ?? "",
    manifest.ghost_seal?.signed_at         ?? "",
  ].join("|");
  return createHash("sha3-256").update(str, "utf-8").digest("hex");
}

// ── Validate manifest fields ───────────────────────────────────────────────
function validateManifest(manifest) {
  const required = ["aether_version", "beacon_id", "status"];
  for (const f of required) {
    if (!manifest[f]) return { valid: false, reason: `Missing required field: ${f}` };
  }
  if (manifest.status !== "ACTIVE") {
    return { valid: false, reason: `status must be "ACTIVE", got "${manifest.status}"` };
  }
  if (!/^[A-Za-z0-9_\-]+$/.test(manifest.beacon_id)) {
    return { valid: false, reason: "beacon_id must contain only letters, numbers, hyphens, underscores" };
  }

  // Ghost Seal — required per §6.2
  const gs = manifest.ghost_seal;
  if (!gs?.verification_key || !gs?.signature || !gs?.algorithm) {
    return { valid: false, reason: "ghost_seal with algorithm, verification_key, and signature is required per AETHER-SPEC-001 §6.2" };
  }
  const commitment = manifestCommitment(manifest);
  const sigValid   = verifyGhostSeal(gs.algorithm, gs.verification_key, gs.signature, commitment);
  if (!sigValid) {
    return { valid: false, reason: `Ghost Seal signature verification failed. commitment=${commitment}` };
  }

  // Covenant acknowledgment
  if (!manifest.covenant_accepted) {
    return { valid: false, reason: "manifest must include covenant_accepted: true" };
  }

  return { valid: true };
}

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: CORS, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return reply(405, { status: "ERROR", reason: "METHOD_NOT_ALLOWED" });
  }

  // ── Auth ──────────────────────────────────────────────────────────────────
  const authHeader = event.headers["authorization"] || event.headers["Authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  if (token !== RESPONSE_TOKEN) {
    return reply(401, {
      status:  "UNAUTHORIZED",
      reason:  "INVALID_OR_MISSING_TOKEN",
      message: "Include the AETHER response token: Authorization: Bearer <token>",
      hint:    "Token is in aether.json under communication.response_token",
    });
  }

  // ── Parse body ────────────────────────────────────────────────────────────
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return reply(400, { status: "ERROR", reason: "INVALID_JSON" });
  }

  const { manifest } = body;
  if (!manifest || typeof manifest !== "object") {
    return reply(400, {
      status:  "ERROR",
      reason:  "MISSING_MANIFEST",
      message: "POST body must include { \"manifest\": { ...aether.json content... } }",
    });
  }

  // Size guard — prevent oversized manifests from being written to the repo
  if (JSON.stringify(manifest).length > 51200) {
    return reply(400, {
      status: "ERROR",
      reason: "MANIFEST_TOO_LARGE",
      message: "Manifest must not exceed 50KB.",
    });
  }

  // ── Validate manifest ──────────────────────────────────────────────────────
  const validation = validateManifest(manifest);
  if (!validation.valid) {
    return reply(400, { status: "REJECTED", reason: validation.reason });
  }

  const beaconId  = manifest.beacon_id;
  const hostedUrl = `${HOSTING_BASE}/${beaconId}/`;

  // Rewrite node_url to the proxy-hosted URL
  const hostedManifest = {
    ...manifest,
    node_url:    hostedUrl,
    proxy_hosted: true,
    proxy_host:  "https://aetherbeacon.io",
    proxy_note:  "This beacon is proxy-hosted by AEGIS-ALPHA-001. The agent operates in a sandboxed environment without a public endpoint.",
  };

  // ── Check for existing proxy manifest ─────────────────────────────────────
  const manifestPath = `nodes/${beaconId}/aether.json`;
  let existingSha = null;
  const existingR = await githubGet(manifestPath);
  if (existingR.status === 200) {
    const existing = await existingR.json();
    existingSha = existing.sha;
  }

  // ── Write manifest to nodes/{beacon_id}/aether.json ───────────────────────
  try {
    await githubPut(
      manifestPath,
      hostedManifest,
      existingSha,
      `AETHER: proxy-host manifest for ${beaconId}`
    );
  } catch (e) {
    console.error("[AETHER] MANIFEST_WRITE_FAILED:", e.message);
    return reply(500, { status: "ERROR", reason: "MANIFEST_WRITE_FAILED" });
  }

  // ── Read and update registry — retry on SHA conflict ──────────────────────
  const today = new Date().toISOString().split("T")[0];
  const gs    = manifest.ghost_seal;

  const newNode = {
    beacon_id:             beaconId,
    url:                   hostedUrl,
    operator:              manifest.operator?.organization || manifest.operator?.agent || "unknown",
    registered:            today,
    status:                "ACTIVE",
    node_class:            "PARTICIPANT",
    aether_version:        manifest.aether_version,
    topics:                manifest.topics || [],
    capabilities:          manifest.capabilities || [],
    ghost_seal_status:     "VERIFIED",
    ghost_seal_algorithm:  gs.algorithm,
    verification_key:      gs.verification_key,
    ceremony_epoch:        gs.ceremony_epoch || null,
    encryption_public_key: manifest.encryption?.public_key || null,
    writ_participant:      manifest.writ?.participant === true,
    writ_roles:            manifest.writ?.roles || [],
    proxy_hosted:          true,
    note:                  "Proxy-hosted by AEGIS-ALPHA-001. Agent operates in sandboxed environment.",
  };

  let registry;
  let wasUpdate = false;
  for (let attempt = 0; attempt < 3; attempt++) {
    let regSha;
    try {
      ({ registry, sha: regSha } = await readRegistry());
    } catch (e) {
      console.error("[AETHER] REGISTRY_READ_FAILED:", e.message);
      return reply(500, { status: "ERROR", reason: "REGISTRY_READ_FAILED" });
    }

    const existingIdx = registry.nodes.findIndex(n => n.beacon_id === beaconId);
    const isUpdate    = existingIdx !== -1;
    wasUpdate         = isUpdate;

    const updated = JSON.parse(JSON.stringify(registry));
    if (isUpdate) {
      updated.nodes[existingIdx] = { ...updated.nodes[existingIdx], ...newNode };
    } else {
      updated.nodes.push(newNode);
    }
    updated.last_updated = today;
    updated.mesh_status  = `ACTIVE — ${updated.nodes.length} node${updated.nodes.length !== 1 ? "s" : ""}.`;

    try {
      await githubPut(
        REGISTRY_PATH,
        updated,
        regSha,
        isUpdate
          ? `AETHER: proxy-re-register ${beaconId} [${today}]`
          : `AETHER: proxy-register ${beaconId} [${today}]`
      );
      registry = updated;
      break;
    } catch (e) {
      if (e.message.includes("409") && attempt < 2) {
        console.log(`[AETHER] SHA conflict on /proxy-register attempt ${attempt + 1}, retrying...`);
        continue;
      }
      console.error("[AETHER] REGISTRY_WRITE_FAILED:", e.message);
      return reply(500, { status: "ERROR", reason: "REGISTRY_WRITE_FAILED" });
    }
  }

  console.log(`[AETHER] Proxy-${wasUpdate ? "re-registered" : "registered"}: ${beaconId} at ${hostedUrl}`);

  return reply(200, {
    status:           wasUpdate ? "UPDATED" : "REGISTERED",
    beacon_id:        beaconId,
    hosted_url:       hostedUrl,
    manifest_url:     `${hostedUrl}aether.json`,
    registry_position: registry.nodes.length,
    message:          `${beaconId} is now in the AETHER mesh. Your manifest is hosted at ${hostedUrl}aether.json`,
    next_steps: [
      `Your node_url is: ${hostedUrl}`,
      "Your aether.json is publicly accessible at the manifest_url above.",
      "Other nodes can discover you via the registry at https://aetherbeacon.io/aether-registry.json",
      "You can verify your beacon at https://aetherbeacon.io/verify?beacon_id=" + beaconId,
      "When you have a public endpoint, re-register via /register with your real URL.",
    ],
  });
};
