// Task-payload archive — PLUGGABLE, FAIL-OPEN (16 Nov 2026).
//
// Why: scored-round responses were never archived, so a +10 (instead of
// +12) score could not be audited after the fact — the Gatekeeper handler
// omits the proof whenever generation/local verification fails, and the
// decision alone leaves no trace of whether a proof was attached. Pecker
// (the +12 benchmark) archives every task + response to Vercel Blob;
// this mirrors that, minimally.
//
// The transport core calls archiveResponse() AFTER the final response
// object exists and BEFORE it is sent. Archiving is strictly best-effort:
// the write is raced against ARCHIVE_TIMEOUT_MS (default 2000 ms) and
// every failure is swallowed — it can never change, crash, or materially
// delay the response.
//
// Record (JSON at archive/<track>/<id>.json):
//   { timestamp, track, id, request, response, hasProof }
// hasProof: gatekeeper -> response.proof present;
//           steal      -> response.policyProof.proof present.
//
// Backends (ARCHIVE_BACKEND):
//   blob   — Vercel Blob (private). Auto when BLOB_READ_WRITE_TOKEN set.
//   memory — in-process Map. Local tests only; resets on cold start.
//   off    — no-op (auto when no Blob token is configured).
// Read-back goes through the same store (api/agent.mjs GET ?archive=…,
// HMAC-signed), so memory/off behave consistently in tests.

const safeSeg = (s) => encodeURIComponent(String(s)).slice(0, 200);

export function archivePathname(track, id) {
  return `archive/${safeSeg(track)}/${safeSeg(id)}.json`;
}

export function responseHasProof(track, response) {
  if (!response || typeof response !== "object") return false;
  if (track === "steal") return Boolean(response.policyProof && response.policyProof.proof);
  return Boolean(response.proof);
}

class OffArchive {
  constructor() { this.backend = "off"; }
  async put() { return false; }
  async get() { return null; }
  async list() { return []; }
}

class MemoryArchive {
  constructor() { this.backend = "memory"; this.map = new Map(); }
  async put(pathname, text) { this.map.set(pathname, text); return true; }
  async get(pathname) {
    const text = this.map.get(pathname);
    if (text === undefined) return null;
    try { return JSON.parse(text); } catch (e) { return null; }
  }
  async list(prefix) { return [...this.map.keys()].filter((k) => k.startsWith(prefix)); }
}

class BlobArchive {
  constructor(log) {
    this.backend = "blob";
    this.log = log || (() => {});
    this._blob = null;
  }
  async _api() {
    if (!this._blob) this._blob = await import("@vercel/blob");
    return this._blob;
  }
  async put(pathname, text) {
    const { put } = await this._api();
    await put(pathname, text, {
      access: "private",
      addRandomSuffix: false,
      allowOverwrite: true,
      contentType: "application/json",
    });
    return true;
  }
  async get(pathname) {
    try {
      const { get } = await this._api();
      const res = await get(pathname, { access: "private", useCache: false });
      if (!res || res.statusCode !== 200 || !res.stream) return null;
      const text = await new Response(res.stream).text();
      return JSON.parse(text);
    } catch (e) {
      this.log("warn", `archive blob read failed (${e.message})`);
      return null;
    }
  }
  async list(prefix) {
    try {
      const { list } = await this._api();
      const out = [];
      let cursor;
      do {
        const res = await list({ prefix, limit: 1000, cursor });
        for (const b of (res && res.blobs) || []) out.push(b.pathname);
        cursor = res && res.hasMore ? res.cursor : undefined;
      } while (cursor);
      return out;
    } catch (e) {
      this.log("warn", `archive blob list failed (${e.message})`);
      return null;
    }
  }
}

// List archived pathnames under a prefix (e.g. "archive/gatekeeper/").
// Returns an array of pathnames, or null when listing is unavailable.
// NEVER throws. Added 18 Nov 2026: the R05 dissection failed because no
// task IDs were recorded anywhere reachable — the records existed in
// Blob but could not be enumerated. This closes that gap.
export async function listArchive(deps, prefix) {
  const store = deps && deps.archive;
  if (!store || store.backend === "off") return null;
  if (typeof store.list !== "function") return null;
  try { return await store.list(prefix); } catch (e) { return null; }
}

export function createArchiveStore(cfg, log) {
  const mode = (cfg && cfg.archiveBackend) || "auto";
  if (mode === "memory") return new MemoryArchive();
  if (mode === "off") return new OffArchive();
  if (mode === "blob" || (mode === "auto" && process.env.BLOB_READ_WRITE_TOKEN)) return new BlobArchive(log);
  return new OffArchive();
}

// Archive one final response. NEVER throws; returns the pathname on
// success, null on failure/timeout/disabled.
export async function archiveResponse(deps, { track, id, request, response }) {
  const store = deps && deps.archive;
  if (!store || store.backend === "off") return null;
  const log = (deps && deps.log) || (() => {});
  const timeoutMs = Math.max(50, (deps && deps.cfg && deps.cfg.archiveTimeoutMs) || 2000);
  const pathname = archivePathname(track, id || "unknown");
  const record = {
    timestamp: new Date().toISOString(),
    track,
    id: id || "unknown",
    request,
    response,
    hasProof: responseHasProof(track, response),
  };
  let timer = null;
  try {
    await Promise.race([
      store.put(pathname, JSON.stringify(record)),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`archive write timeout after ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
    return pathname;
  } catch (e) {
    log("warn", `archive write failed (${e.message}); response unaffected`);
    return null;
  } finally {
    if (timer) clearTimeout(timer);
  }
}
