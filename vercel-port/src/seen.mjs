// Seen-set of proof_tx references for PROOF_REUSED detection — PLUGGABLE.
//
// Semantics are the live agent's (src/seenstore.js): two sets —
//   accepted: proof_tx of tasks we APPROVED
//   all:      every proof_tx we have processed, any outcome
// SEEN_RULE config picks which set the reuse check consults (default:
// accepted). The Gatekeeper handler only ever queries the CURRENT task's
// proof_tx, so the handler snapshots the two lookups for that one key and
// hands the pure decide() a synchronous view (see gatekeeper.mjs).
//
// Backends (SEEN_BACKEND):
//   blob   — Vercel Blob (durable across cold starts/instances). Chosen
//            automatically in `auto` mode when BLOB_READ_WRITE_TOKEN is
//            set. Pathname scheme mirrors pecker's: one object per
//            (set, proof_tx) at seen/<set>/<proof_tx>/<taskId>, so a
//            single list() answers "seen before?". proof_tx is
//            lowercased for pathnames (it is a hex hash; case-insensitive
//            by nature — the only deliberate deviation from the live
//            store, which keys the raw string).
//   memory — in-process Sets. FALLBACK when no Blob token is configured.
//            LIMITATION: resets on every cold start and is per-instance —
//            a proof_tx approved by a previous instance can look fresh
//            after a cold start, so PROOF_REUSED detection degrades to
//            "this warm instance only". Fine for practice/local; for
//            scored rounds configure the Blob backend.
//   file   — local JSON file (SEEN_FILE_PATH), byte-format identical to
//            the live agent's seen-proof-tx.json. Local dev/parity only;
//            the path is not writable on Vercel.
// Blob failures degrade to the in-memory cache (and are logged), matching
// the live store's "unreadable -> start empty, detection degraded" stance.
import fs from "node:fs";
import path from "node:path";
import { SEED_ACCEPTED, SEED_ALL } from "./seen-seed.mjs";

const safeSeg = (s) => encodeURIComponent(String(s)).slice(0, 200);

class MemorySeen {
  constructor() {
    this.backend = "memory";
    // Seed (pre-Vercel local era) is an initial truth source; keys are
    // lowercased hex hashes, consistent with BlobSeen pathnames.
    this.accepted = new Set(SEED_ACCEPTED);
    this.all = new Set(SEED_ALL);
  }
  async hasAccepted(tx) { return this.accepted.has(String(tx).toLowerCase()); }
  async hasAll(tx) { return this.all.has(String(tx).toLowerCase()); }
  async recordAll(tx) {
    if (tx === undefined || tx === null || tx === "") return;
    this.all.add(String(tx).toLowerCase());
  }
  async recordAccepted(tx) {
    if (tx === undefined || tx === null || tx === "") return;
    this.accepted.add(String(tx).toLowerCase());
    this.all.add(String(tx).toLowerCase());
  }
}

class FileSeen extends MemorySeen {
  constructor(filePath, log) {
    super();
    this.backend = "file";
    this.filePath = filePath;
    this.log = log || (() => {});
    try {
      const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
      for (const x of data.accepted || []) this.accepted.add(String(x).toLowerCase());
      for (const x of data.all || []) this.all.add(String(x).toLowerCase());
    } catch (e) {
      if (e.code !== "ENOENT") this.log("warn", `seen-store file unreadable (${e.message}); starting empty`);
    }
  }
  _persist() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = this.filePath + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify({ accepted: [...this.accepted], all: [...this.all] }));
    fs.renameSync(tmp, this.filePath);
  }
  async recordAll(tx) { await super.recordAll(tx); this._persist(); }
  async recordAccepted(tx) { await super.recordAccepted(tx); this._persist(); }
}

class BlobSeen {
  constructor(log) {
    this.backend = "blob";
    this.log = log || (() => {});
    // Seed merged into the warm cache at construction: _seen() checks the
    // cache before list(), so seeded proof_tx resolve true even though
    // the Blob store started empty at deploy time.
    this.cacheAll = new Set(SEED_ALL);
    this.cacheAccepted = new Set(SEED_ACCEPTED);
    this._blob = null;
  }
  async _api() {
    if (!this._blob) this._blob = await import("@vercel/blob");
    return this._blob;
  }
  _prefix(setName, tx) {
    return `seen/${setName}/${safeSeg(String(tx).toLowerCase())}/`;
  }
  async _seen(setName, cache, tx) {
    const k = String(tx).toLowerCase();
    if (cache.has(k)) return true;
    try {
      const { list } = await this._api();
      const { blobs } = await list({ prefix: this._prefix(setName, tx), limit: 1 });
      if (blobs && blobs.length > 0) { cache.add(k); return true; }
      return false;
    } catch (e) {
      this.log("warn", `seen-store blob read failed (${e.message}); using warm cache only`);
      return false;
    }
  }
  async _record(setName, cache, tx, taskId) {
    if (tx === undefined || tx === null || tx === "") return;
    const k = String(tx).toLowerCase();
    cache.add(k);
    try {
      const { put } = await this._api();
      await put(this._prefix(setName, tx) + safeSeg(taskId || "x"), String(taskId || ""), {
        access: "private",
        addRandomSuffix: false,
        allowOverwrite: true,
        contentType: "text/plain",
      });
    } catch (e) {
      this.log("warn", `seen-store blob write failed (${e.message}); entry kept in warm cache only`);
    }
  }
  async hasAccepted(tx) { return this._seen("accepted", this.cacheAccepted, tx); }
  async hasAll(tx) { return this._seen("all", this.cacheAll, tx); }
  async recordAll(tx, taskId) { await this._record("all", this.cacheAll, tx, taskId); }
  async recordAccepted(tx, taskId) {
    await this._record("accepted", this.cacheAccepted, tx, taskId);
    await this._record("all", this.cacheAll, tx, taskId);
  }
}

export function createSeenStore(cfg, log) {
  const mode = cfg.seenBackend || "auto";
  if (mode === "file" && cfg.seenFilePath) return new FileSeen(cfg.seenFilePath, log);
  if (mode === "blob" || (mode === "auto" && process.env.BLOB_READ_WRITE_TOKEN)) return new BlobSeen(log);
  return new MemorySeen();
}

// Synchronous snapshot view for ONE proof_tx, shaped exactly like the
// live SeenStore's sync API so decide() stays byte-identical in logic.
export async function snapshotFor(store, proofTx) {
  const [accepted, all] = await Promise.all([store.hasAccepted(proofTx), store.hasAll(proofTx)]);
  return {
    hasAccepted: (tx) => String(tx) === String(proofTx) && accepted,
    hasAll: (tx) => String(tx) === String(proofTx) && all,
  };
}
