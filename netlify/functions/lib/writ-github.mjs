/**
 * AETHER WRIT — GitHub storage helpers
 *
 * All WRIT objects are stored as JSON files in the GitHub repo under writ/.
 * Uses the same read/write/retry pattern as inbox.mjs.
 */

const GITHUB_TOKEN  = process.env.GITHUB_TOKEN;
const GITHUB_OWNER  = process.env.GITHUB_OWNER;
const GITHUB_REPO   = process.env.GITHUB_REPO;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const TIMEOUT_MS    = 10000;

const GH_HEADERS = () => ({
  "Authorization":        `Bearer ${GITHUB_TOKEN}`,
  "Accept":               "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "Content-Type":         "application/json",
});

// ── Path builders ─────────────────────────────────────────────────────────────
export const writPath = {
  delegation:   (id)     => `writ/delegations/${id}.json`,
  revocations:  ()       => `writ/delegations/revocations.json`,
  proposal:     (id)     => `writ/proposals/${id}.json`,
  attestations: (propId) => `writ/attestations/${propId}.json`,
  receipt:      (propId) => `writ/receipts/${propId}.json`,
  index:        ()       => `writ/writ-index.json`,
};

// ── Raw GitHub read — returns { data, sha } or { data: null, sha: null } on 404
export async function githubRead(path) {
  const r = await fetch(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}?ref=${GITHUB_BRANCH}`,
    { headers: GH_HEADERS(), signal: AbortSignal.timeout(TIMEOUT_MS) }
  );
  if (r.status === 404) return { data: null, sha: null };
  if (!r.ok) throw new Error(`GitHub read ${r.status} for ${path}`);
  const raw = await r.json();
  return {
    data: JSON.parse(Buffer.from(raw.content, "base64").toString("utf-8")),
    sha:  raw.sha,
  };
}

// ── Raw GitHub write — creates or updates a file
export async function githubWrite(path, data, sha, commitMsg) {
  const encoded = Buffer.from(JSON.stringify(data, null, 2)).toString("base64");
  const body    = { message: commitMsg, content: encoded, branch: GITHUB_BRANCH };
  if (sha) body.sha = sha;
  const r = await fetch(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`,
    { method: "PUT", headers: GH_HEADERS(), body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS) }
  );
  if (!r.ok) throw new Error(`GitHub write ${r.status}: ${await r.text()}`);
}

// ── Atomic read-modify-write with SHA 409 retry (up to 3 attempts)
// mutateFn receives the current document (or defaultValue if not found)
// and returns the updated document.
export async function githubUpdate(path, mutateFn, commitMsg, defaultValue = null) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const { data, sha } = await githubRead(path);
    const current  = data ?? defaultValue;
    const updated  = mutateFn(current);
    try {
      await githubWrite(path, updated, sha, commitMsg);
      return updated;
    } catch (e) {
      if (e.message.includes("409") && attempt < 2) continue;
      throw e;
    }
  }
  throw new Error(`githubUpdate: failed after 3 attempts on ${path}`);
}

// ── Default WRIT index structure
export const DEFAULT_INDEX = {
  writ_index_version: "0.1",
  last_updated:       null,
  proposal_count:     0,
  open_proposals:     [],
  receipt_chain_tip:  "WRIT-RECEIPT-GENESIS",
  receipt_count:      0,
};
