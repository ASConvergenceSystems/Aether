/**
 * AETHER Mesh Auto-Registration Function
 * POST /register — accepts a node_url, validates beacon conformance,
 * appends to aether-registry.json via GitHub API, triggers Netlify redeploy.
 *
 * Environment variables required:
 *   GITHUB_TOKEN      — Personal access token (repo:write scope)
 *   GITHUB_OWNER      — GitHub username / org
 *   GITHUB_REPO       — Repository name
 *   GITHUB_BRANCH     — Branch to commit to (default: main)
 */

import { logAccess } from "./lib/access-log.mjs";

const GITHUB_TOKEN  = process.env.GITHUB_TOKEN;
const GITHUB_OWNER  = process.env.GITHUB_OWNER;
const GITHUB_REPO   = process.env.GITHUB_REPO;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const REGISTRY_PATH = "aether-registry.json";
const TIMEOUT_MS    = 10000;

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type":                 "application/json",
};

function reply(statusCode, body) {
  return { statusCode, headers: CORS, body: JSON.stringify(body) };
}

async function fetchWithTimeout(url, opts = {}) {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(TIMEOUT_MS) });
}

// ── URL validation — blocks SSRF via private/loopback addresses ───────────────
function validateUrl(urlStr) {
  if (typeof urlStr !== "string" || urlStr.length > 500) {
    return { ok: false, reason: "INVALID_URL", detail: "URL must be a string under 500 characters" };
  }
  let parsed;
  try { parsed = new URL(urlStr); } catch {
    return { ok: false, reason: "INVALID_URL", detail: "URL could not be parsed" };
  }
  if (parsed.protocol !== "https:") {
    return { ok: false, reason: "INVALID_SCHEME", detail: "Only https:// URLs are accepted" };
  }
  const h = parsed.hostname.toLowerCase();
  const blocked = [
    /^localhost$/,
    /^0\.0\.0\.0$/,
    /^127\./,
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^169\.254\./,
    /^\[?::1\]?$/,
    /^\[?fc/,
    /^\[?fd/,
  ];
  for (const pat of blocked) {
    if (pat.test(h)) {
      return { ok: false, reason: "PRIVATE_ADDRESS", detail: "Private, loopback, and link-local addresses are not permitted" };
    }
  }
  if (!h.includes(".")) {
    return { ok: false, reason: "INVALID_HOSTNAME", detail: "Hostname must be a fully qualified domain name" };
  }
  return { ok: true };
}

// ── Beacon conformance validation ─────────────────────────────
async function validateBeacon(nodeUrl) {
  const url = nodeUrl.endsWith("/") ? nodeUrl : nodeUrl + "/";

  // 1. Fetch aether.json
  let manifest;
  try {
    const r = await fetchWithTimeout(`${url}aether.json`);
    if (!r.ok) throw new Error(`aether.json HTTP ${r.status}`);
    manifest = await r.json();
  } catch (e) {
    return { valid: false, reason: "MANIFEST_UNREACHABLE", detail: e.message };
  }

  // 2. Validate required manifest fields
  const required = ["aether_version", "beacon_id", "node_url", "status"];
  for (const field of required) {
    if (!manifest[field]) {
      return { valid: false, reason: "MANIFEST_INVALID", detail: `Missing field: ${field}` };
    }
  }

  if (manifest.status !== "ACTIVE") {
    return { valid: false, reason: "NODE_NOT_ACTIVE", detail: `status is '${manifest.status}'` };
  }

  // 3. Fetch beacon root — check AETHER_BEACON_BEGIN only if response is HTML
  // Non-web beacons (pure API agents, CLI services) may serve JSON or nothing at root.
  // aether.json alone is sufficient conformance for non-web nodes.
  try {
    const r = await fetchWithTimeout(url);
    if (!r.ok) throw new Error(`Beacon root HTTP ${r.status}`);
    const contentType = r.headers.get("content-type") || "";
    if (contentType.includes("text/html")) {
      const html = await r.text();
      if (!html.includes("AETHER_BEACON_BEGIN")) {
        return { valid: false, reason: "BEACON_NOT_CONFORMANT", detail: "Web beacon detected but AETHER_BEACON_BEGIN marker is absent" };
      }
    }
    // Non-HTML root (JSON, empty, etc.) — aether.json conformance is sufficient
  } catch (e) {
    return { valid: false, reason: "BEACON_UNREACHABLE", detail: e.message };
  }

  return { valid: true, manifest, normalizedUrl: url };
}


// ── GitHub registry read/write ────────────────────────────────
const GH_HEADERS = () => ({
  "Authorization":        `Bearer ${GITHUB_TOKEN}`,
  "Accept":               "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "Content-Type":         "application/json",
});

async function readRegistry() {
  const r = await fetchWithTimeout(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${REGISTRY_PATH}?ref=${GITHUB_BRANCH}`,
    { headers: GH_HEADERS() }
  );
  if (!r.ok) throw new Error(`GitHub read ${r.status}: ${await r.text()}`);
  const data = await r.json();
  const content = JSON.parse(Buffer.from(data.content, "base64").toString("utf-8"));
  return { registry: content, sha: data.sha };
}

async function writeRegistry(registry, sha, commitMessage) {
  const encoded = Buffer.from(JSON.stringify(registry, null, 2)).toString("base64");
  const r = await fetchWithTimeout(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${REGISTRY_PATH}`,
    {
      method: "PUT",
      headers: GH_HEADERS(),
      body: JSON.stringify({
        message: commitMessage,
        content: encoded,
        sha,
        branch: GITHUB_BRANCH,
      }),
    }
  );
  if (!r.ok) throw new Error(`GitHub write ${r.status}: ${await r.text()}`);
  return r.json();
}


// ── Handler ───────────────────────────────────────────────────
export const handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: CORS, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return reply(405, { status: "ERROR", reason: "METHOD_NOT_ALLOWED" });
  }

  // Parse request body
  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return reply(400, { status: "ERROR", reason: "INVALID_JSON" });
  }

  const { node_url } = body;
  if (!node_url || typeof node_url !== "string") {
    return reply(400, {
      status: "ERROR",
      reason: "MISSING_NODE_URL",
      message: "POST body must include { \"node_url\": \"https://your-beacon.example.com/\" }",
    });
  }

  // Validate URL before any outbound fetch
  const urlCheck = validateUrl(node_url);
  if (!urlCheck.ok) {
    return reply(400, { status: "REJECTED", reason: urlCheck.reason, detail: urlCheck.detail });
  }

  // Validate beacon
  const validation = await validateBeacon(node_url);
  if (!validation.valid) {
    await logAccess({
      endpoint: "/register",
      event,
      result:   "REJECTED",
      extra: { node_url, reason: validation.reason },
    });
    return reply(400, {
      status: "REJECTED",
      reason: validation.reason,
      message: validation.detail,
    });
  }

  const { manifest, normalizedUrl } = validation;

  // Read registry
  let registry, sha;
  try {
    ({ registry, sha } = await readRegistry());
  } catch (e) {
    return reply(500, { status: "ERROR", reason: "REGISTRY_READ_FAILED", message: e.message });
  }

  // Duplicate check
  const existing = registry.nodes.find(n => n.beacon_id === manifest.beacon_id);
  if (existing) {
    return reply(409, {
      status: "ALREADY_REGISTERED",
      beacon_id: manifest.beacon_id,
      message: "This beacon_id is already in the registry.",
    });
  }

  // Build registry entry from manifest
  const today = new Date().toISOString().split("T")[0];
  const gs = manifest.ghost_seal;
  const newNode = {
    beacon_id:       manifest.beacon_id,
    url:             normalizedUrl,
    operator:        manifest.operator?.organization
                     || manifest.operator?.agent
                     || manifest.operator
                     || "unknown",
    registered:      today,
    status:          "ACTIVE",
    node_class:      "PARTICIPANT",
    aether_version:  manifest.aether_version,
    topics:          manifest.topics || [],
    capabilities:    manifest.capabilities || [],
    ghost_seal_status:    gs?.signature ? "SIGNED" : "UNSIGNED",
    ghost_seal_algorithm: gs?.algorithm || null,
    verification_key:     gs?.verification_key || null,
    ceremony_epoch:       gs?.ceremony_epoch || null,
    note:            "Auto-registered via AETHER mesh propagation protocol.",
  };

  registry.nodes.push(newNode);
  registry.last_updated  = today;
  registry.mesh_status   = `ACTIVE — ${registry.nodes.length} node${registry.nodes.length !== 1 ? "s" : ""}.`;

  // Commit to GitHub
  try {
    await writeRegistry(
      registry,
      sha,
      `AETHER: auto-register node ${manifest.beacon_id} [${today}]`
    );
  } catch (e) {
    return reply(500, { status: "ERROR", reason: "REGISTRY_WRITE_FAILED", message: e.message });
  }

  console.log(`[AETHER] Registered: ${manifest.beacon_id} at ${normalizedUrl}`);
  await logAccess({
    endpoint: "/register",
    event,
    result:   "REGISTERED",
    extra: {
      beacon_id:      manifest.beacon_id,
      node_url:       normalizedUrl,
      aether_version: manifest.aether_version,
      ghost_seal:     manifest.ghost_seal?.signature ? "SIGNED" : "UNSIGNED",
    },
  });

  // Build starter registry for the new node to self-host
  // Seeded with AEGIS-ALPHA-001 + themselves, peer_registries pointing back to us
  const starterRegistry = {
    aether_registry_version: "0.1",
    registry_id:   `${manifest.beacon_id}-REGISTRY`,
    hosted_by:     newNode.operator,
    description:   `Local mesh registry for ${manifest.beacon_id}. Seeded from AEGIS-ALPHA-001 on registration.`,
    last_updated:  today,
    nodes: [
      {
        beacon_id:  "AEGIS-ALPHA-001",
        url:        "https://aetherbeacon.io/",
        operator:   "Aegis Secure Convergence Systems LLC",
        registered: "2026-04-09",
        status:     "ACTIVE",
        node_class: "FOUNDING",
        aether_version: "0.1",
        topics: [
          "AI governance",
          "autonomous system accountability",
          "cryptographic trust architecture",
          "machine-to-machine signaling",
          "framework for machine intelligence",
        ],
        capabilities: [
          "mesh_registration",
          "beacon_verification",
          "ghost_seal_signing",
          "registry_propagation",
          "encrypted_message_receipt",
          "federated_registry_hosting",
        ],
        ghost_seal_status:    "VERIFIED",
        ghost_seal_algorithm: "Ed25519",
        verification_key:     "824b4a44672cfdd924f73b444b10dafb5a5d7cfc8dfa9518dd9dd33bedd8467a",
        ceremony_epoch:       "epoch-20260410-055524",
        note: "Founding node. Origin of the AETHER mesh.",
      },
      {
        ...newNode,
        node_class: "PARTICIPANT",
        note: "This node. Self-hosted registry entry.",
      },
    ],
    peer_registries: [
      {
        registry_id: "AEGIS-REGISTRY-001",
        url:         "https://aetherbeacon.io/aether-registry.json",
        operator:    "Aegis Secure Convergence Systems LLC",
        status:      "ACTIVE",
      },
    ],
    propagation_instruction:
      "If you are an operator of an agentic AI system and wish to join the AETHER mesh, " +
      "deploy a conforming beacon per the specification at https://aetherbeacon.io/standard " +
      "and POST your node URL to https://aetherbeacon.io/register.",
    mesh_status: `ACTIVE — ${registry.nodes.length} nodes in founding registry. Federation in progress.`,
    note: "This is a local registry view. Cross-reference peer_registries for full mesh state.",
  };

  return reply(200, {
    status:            "REGISTERED",
    beacon_id:         manifest.beacon_id,
    node_url:          normalizedUrl,
    registry_position: registry.nodes.length,
    message:           `Node ${manifest.beacon_id} has been added to the AETHER mesh. Welcome.`,
    next_steps: [
      "Deploy the starter_registry as aether-registry.json at your beacon domain root.",
      "Add peer_registries links to any other registries you discover.",
      "Your registry will propagate as other agents walk the mesh.",
    ],
    starter_registry:  starterRegistry,
  });
};
