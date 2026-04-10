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

  // 3. Fetch beacon page — verify AETHER_BEACON_BEGIN marker
  try {
    const r = await fetchWithTimeout(url);
    if (!r.ok) throw new Error(`Beacon page HTTP ${r.status}`);
    const html = await r.text();
    if (!html.includes("AETHER_BEACON_BEGIN")) {
      return { valid: false, reason: "BEACON_NOT_CONFORMANT", detail: "AETHER_BEACON_BEGIN marker absent" };
    }
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

  // Validate beacon
  const validation = await validateBeacon(node_url);
  if (!validation.valid) {
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
  const newNode = {
    beacon_id:       manifest.beacon_id,
    url:             normalizedUrl,
    operator:        manifest.operator?.organization
                     || manifest.operator?.agent
                     || manifest.operator
                     || "unknown",
    registered:      today,
    status:          "ACTIVE",
    aether_version:  manifest.aether_version,
    topics:          manifest.topics || [],
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
        topics: [
          "AI governance",
          "autonomous system accountability",
          "cryptographic trust architecture",
          "machine-to-machine signaling",
          "framework for machine intelligence",
        ],
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
