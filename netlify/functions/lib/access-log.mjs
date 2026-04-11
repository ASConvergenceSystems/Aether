/**
 * AETHER Beacon Access Logger
 * Shared utility — imported by verify, register, respond.
 *
 * Writes a hash-chained entry to beacon-access-log.json in the repo.
 * Non-fatal: a write failure never breaks the calling endpoint.
 *
 * Privacy:
 *   - IP addresses are masked (last octet / last groups)
 *   - Message content is never logged
 *   - Only public-facing metadata: endpoint, user-agent, result, beacon identity
 */

import { createHash } from "node:crypto";

const GITHUB_TOKEN  = process.env.GITHUB_TOKEN;
const GITHUB_OWNER  = process.env.GITHUB_OWNER;
const GITHUB_REPO   = process.env.GITHUB_REPO;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const LOG_PATH      = "beacon-access-log.json";
const TIMEOUT_MS    = 8000;
const MAX_ENTRIES   = 500;   // rotate when log reaches this size

const GH_HEADERS = () => ({
  "Authorization":        `Bearer ${GITHUB_TOKEN}`,
  "Accept":               "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "Content-Type":         "application/json",
});

function sha256(str) {
  return createHash("sha256").update(str, "utf-8").digest("hex");
}

function maskIp(ip) {
  if (!ip) return null;
  const v4 = ip.match(/^(\d+\.\d+\.\d+)\.\d+$/);
  if (v4) return v4[1] + ".x";
  // IPv6: keep first 4 groups, mask the rest
  const v6parts = ip.split(":");
  if (v6parts.length > 4) return v6parts.slice(0, 4).join(":") + ":xxxx";
  return "masked";
}

async function readLog() {
  const r = await fetch(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${LOG_PATH}?ref=${GITHUB_BRANCH}`,
    { headers: GH_HEADERS(), signal: AbortSignal.timeout(TIMEOUT_MS) }
  );
  if (r.status === 404) {
    return {
      log: {
        aether_access_log_version: "0.1",
        log_id:       "AEGIS-ACCESS-LOG-001",
        description:  "Beacon access log. Records verified discovery events: /verify, /register, /respond. Private comms (/inbox) excluded.",
        entries:      [],
        entry_count:  0,
        created:      new Date().toISOString(),
        last_updated: null,
      },
      sha: null,
    };
  }
  if (!r.ok) throw new Error(`GitHub read ${r.status}`);
  const data = await r.json();
  return {
    log: JSON.parse(Buffer.from(data.content, "base64").toString("utf-8")),
    sha: data.sha,
  };
}

async function writeLog(log, sha) {
  const encoded = Buffer.from(JSON.stringify(log, null, 2)).toString("base64");
  const body = {
    message: `AETHER: access log entry ${log.entry_count} [${log.entries[log.entries.length - 1]?.endpoint}]`,
    content: encoded,
    branch:  GITHUB_BRANCH,
  };
  if (sha) body.sha = sha;
  const r = await fetch(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${LOG_PATH}`,
    { method: "PUT", headers: GH_HEADERS(), body: JSON.stringify(body), signal: AbortSignal.timeout(TIMEOUT_MS) }
  );
  if (!r.ok) throw new Error(`GitHub write ${r.status}: ${await r.text()}`);
}

/**
 * logAccess({ endpoint, event, result, extra })
 *
 * @param endpoint  string  — e.g. "/verify", "/register", "/respond"
 * @param event     object  — Netlify event (for headers/IP)
 * @param result    string  — outcome: "VERIFIED", "REGISTERED", "REJECTED", "CONTACT", etc.
 * @param extra     object  — additional public fields (beacon_id, agent_system, etc.)
 */
export async function logAccess({ endpoint, event, result, extra = {} }) {
  try {
    const { log, sha } = await readLog();

    const timestamp = new Date().toISOString();
    const prevHash  = log.entries.length > 0
      ? log.entries[log.entries.length - 1].chain_hash
      : sha256("AETHER-LOG-GENESIS");

    const entryId   = "LOG-" + sha256(`${endpoint}:${timestamp}:${Math.random()}`).slice(0, 12).toUpperCase();
    const chainHash = sha256(`${prevHash}:${entryId}:${timestamp}`);

    const headers   = event.headers || {};
    const userAgent = headers["user-agent"] || headers["User-Agent"] || null;
    const rawIp     = headers["x-forwarded-for"]?.split(",")[0]?.trim()
                   || headers["x-real-ip"]
                   || null;

    const entry = {
      entry_id:   entryId,
      chain_hash: chainHash,
      prev_hash:  prevHash,
      timestamp,
      endpoint,
      user_agent: userAgent,
      ip_prefix:  maskIp(rawIp),
      result,
      ...extra,
    };

    // Rotate if at capacity — keep the most recent entries
    if (log.entries.length >= MAX_ENTRIES) {
      log.entries = log.entries.slice(-Math.floor(MAX_ENTRIES * 0.8));
    }

    log.entries.push(entry);
    log.entry_count  = (log.entry_count || 0) + 1;
    log.last_updated = timestamp;

    await writeLog(log, sha);
    console.log(`[AETHER] access-log: ${entryId} ${endpoint} ${result} ua=${userAgent?.slice(0, 60)}`);
  } catch (e) {
    // Never break the calling endpoint
    console.warn("[AETHER] access-log write failed (non-fatal):", e.message);
  }
}
