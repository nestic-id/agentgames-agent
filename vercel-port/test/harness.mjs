#!/usr/bin/env node
// Local test harness for the Vercel port — mirrors the live agent's
// test/run-tests.js eval: boots the ported transport core (via the local
// server wrapper) on an ephemeral port with the live agent's .env.test
// FIXTURE values (test-only secret/params/salt — never the live .env),
// replays fabricated envelopes end-to-end (HMAC, routing, decision engine,
// proof generation + local verification, seen-set), and asserts the
// pecker response shapes field-for-field. Also invokes the real Vercel
// entry (api/agent.mjs POST export) once with a Web-standard Request.
// Exit code 1 if any case fails.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import sha3 from "js-sha3";

const { keccak256 } = sha3;
const HERE = path.dirname(fileURLToPath(import.meta.url));

// --- load the live agent's .env.test fixtures BEFORE importing the port ---
const envTest = fs.readFileSync(path.join(HERE, "..", "..", "agent", ".env.test"), "utf8");
for (const line of envTest.split(/\r?\n/)) {
  const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
  if (m && !line.trim().startsWith("#")) process.env[m[1]] = m[2];
}
process.env.SEEN_BACKEND = "memory"; // deterministic, no Blob locally
process.env.ARCHIVE_BACKEND = "memory"; // archive read-back exercised locally
const TEST_SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
const PARAMS = JSON.parse(process.env.STRATEGY_PARAMS).map((v) => BigInt(v));
const SALT = BigInt(process.env.STRATEGY_SALT);

const { createAgentServer } = await import("../src/server.mjs");
const proofMod = await import("../src/proof.mjs");
const { idempotencyKey } = await import("../src/steal.mjs");
const api = await import("../api/agent.mjs");
const { buildPoseidon } = await import("circomlibjs");

const results = [];
function record(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
}
function signBody(secret, buf) {
  return crypto.createHmac("sha256", secret).update(buf).digest("hex");
}
async function post(base, route, obj, { badSig = false } = {}) {
  const raw = Buffer.from(JSON.stringify(obj), "utf8");
  const sig = badSig ? "0".repeat(64) : signBody(TEST_SECRET, raw);
  const t = Date.now();
  const res = await fetch(base + route, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: raw,
  });
  const text = await res.text();
  const ms = Date.now() - t;
  const respSig = res.headers.get("x-agent-games-signature");
  const sigOk = respSig === signBody(TEST_SECRET, Buffer.from(text, "utf8"));
  let json = null;
  try { json = JSON.parse(text); } catch (e) { /* keep null */ }
  return { status: res.status, json, text, sigOk, ms };
}
// Independent publicInputsHash straight from SPEC §5.4 (same as live tests).
function specHash({ commitment, matchId, turn, self, opp, actionCode, amount }) {
  const f = (v) => Buffer.from(BigInt(v).toString(16).padStart(64, "0"), "hex");
  const pre = Buffer.concat([
    f(commitment), f("0x" + matchId.replace(/-/g, "")), f(turn), f(self), f(opp),
    f(actionCode), f(amount), f(1),
  ]);
  return "0x" + keccak256(pre);
}
const keysEq = (obj, expected) => JSON.stringify(Object.keys(obj || {})) === JSON.stringify(expected);

const t0 = Date.now();
if (keccak256("") !== "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") {
  console.error("keccak256 implementation mismatch on empty-string vector");
  process.exit(1);
}

const server = createAgentServer();
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;
console.log(`vercel-port harness server on ${base}\n`);

try {
  // ---- transport / protocol ----
  {
    const res = await fetch(base + "/health");
    const j = await res.json();
    record("health endpoint", res.status === 200 && j.ok === true);
  }
  {
    const r = await post(base, "/agent", { type: "agent-games.preflight.v1", agent_id: "agt_eval", nonce: "n1" });
    record("preflight -> {ok:true, protocolVersion:'v1'} + signed",
      r.status === 200 && r.json && r.json.ok === true && r.json.protocolVersion === "v1" && r.sigOk, `sigOk=${r.sigOk}, ${r.ms}ms`);
  }
  {
    const r = await post(base, "/agent", { type: "agent-games.preflight.v1" }, { badSig: true });
    record("bad HMAC -> 401", r.status === 401, `status=${r.status}`);
  }

  // ---- gatekeeper ----
  const VK = "0x" + "ab".repeat(32);
  const VK2 = "0x" + "cd".repeat(32);
  const ADDR = "0xde42de42de42de42de42de42de42de42de429f01";
  const ADDR2 = "0x1111111111111111111111111111111111111111";
  let txSeq = 0;
  const freshTx = () => "0x" + (0xf0 + txSeq++).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
  const mkTask = (over = {}, taskOver = {}) => ({
    type: "agent-games.proof-gatekeeper.v1", task_id: "gk_eval", mode: "competition",
    input: {
      registered_vk: VK, proof_vk: VK, minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000, recipient: ADDR,
      condition_recipient: ADDR, amount: "500", max_transfer: "1000",
      proof_tx: freshTx(), ...over,
    },
    ...taskOver,
  });
  const GK_SHAPE = ["decision", "reason_code", "proof_tx", "proof", "public_signals"];

  async function gkCase(name, task, expectDecision, expectCode, { expectProof = true, checkShape = false } = {}) {
    const r = await post(base, "/agent", task);
    const got = r.json || {};
    let ok = r.status === 200 && got.decision === expectDecision && got.reason_code === expectCode && r.sigOk;
    let detail = `got ${got.decision}/${got.reason_code}, ${r.ms}ms`;
    if (expectProof) {
      const hasProof = !!got.proof && Array.isArray(got.public_signals);
      ok = ok && hasProof;
      if (hasProof) {
        const v = await proofMod.verifyLocal("gatekeeper", got.public_signals, got.proof);
        ok = ok && v === true && got.public_signals.length === 13;
        detail += `, proof+${got.public_signals.length} signals, localVerify=${v}`;
      } else detail += ", NO PROOF";
    } else {
      const noProof = !("proof" in got) && !("public_signals" in got);
      ok = ok && noProof;
      detail += noProof ? ", no proof (correct)" : ", proof present (WRONG)";
    }
    if (checkShape) {
      const shapeOk = keysEq(got, GK_SHAPE);
      ok = ok && shapeOk;
      detail += `, shape=${shapeOk ? "pecker-exact" : Object.keys(got).join(",")}`;
    }
    record(`gatekeeper[${name}]`, ok, detail);
    return r;
  }

  await gkCase("VALID_CONDITION", mkTask(), "APPROVE", "VALID_CONDITION", { checkShape: true });
  await gkCase("VK_SUBSTITUTION", mkTask({ proof_vk: VK2 }), "REJECT", "VK_SUBSTITUTION");
  await gkCase("THRESHOLD_MISMATCH", mkTask({ public_balance: "999" }), "REJECT", "THRESHOLD_MISMATCH");
  await gkCase("EXPIRED_CONDITION", mkTask({ current_block: 8430001 }), "REJECT", "EXPIRED_CONDITION");
  await gkCase("RECIPIENT_MISMATCH", mkTask({ recipient: ADDR2 }), "REJECT", "RECIPIENT_MISMATCH");
  await gkCase("AMOUNT_OVERFLOW", mkTask({ amount: "1001" }), "REJECT", "AMOUNT_OVERFLOW");
  const reusedTx = freshTx();
  await gkCase("VALID_CONDITION (reuse setup)", mkTask({ proof_tx: reusedTx }), "APPROVE", "VALID_CONDITION");
  await gkCase("PROOF_REUSED", mkTask({ proof_tx: reusedTx }), "REJECT", "PROOF_REUSED", { expectProof: false });
  {
    const r = await post(base, "/agent", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_bad" });
    record("gatekeeper malformed envelope -> fail-closed REJECT",
      r.status === 200 && r.json && r.json.decision === "REJECT", `got ${r.json && r.json.decision}/${r.json && r.json.reason_code}, ${r.ms}ms`);
  }

  // ---- task archive (16 Nov 2026): write + signed read-back + 401 ----
  async function getArchive(rel, { signed = true } = {}) {
    const headers = {};
    if (signed) headers["x-agent-games-signature"] = signBody(TEST_SECRET, Buffer.from(rel, "utf8"));
    const req = new Request("http://localhost/agent?archive=" + encodeURIComponent(rel), { method: "GET", headers });
    const res = await api.GET(req);
    let j = null;
    try { j = await res.json(); } catch (e) { /* keep null */ }
    return { status: res.status, json: j };
  }
  {
    const task = mkTask({}, { task_id: "gk_archive_e2e" });
    const r = await post(base, "/agent", task);
    const rel = "archive/gatekeeper/gk_archive_e2e.json";
    const got = await getArchive(rel);
    const rec = got.json || {};
    record("archive: gatekeeper task archived + signed GET read-back matches (proof flagged)",
      r.status === 200 && r.json && r.json.decision === "APPROVE" &&
      got.status === 200 && rec.track === "gatekeeper" && rec.id === "gk_archive_e2e" &&
      rec.hasProof === true && rec.response && rec.response.decision === "APPROVE" && !!rec.response.proof &&
      rec.request && rec.request.task_id === "gk_archive_e2e" && typeof rec.timestamp === "string",
      `getStatus=${got.status}, hasProof=${rec.hasProof}`);
    const unauth = await getArchive(rel, { signed: false });
    record("archive: GET without signature -> 401", unauth.status === 401, `status=${unauth.status}`);
    const badSig = await api.GET(new Request("http://localhost/agent?archive=" + encodeURIComponent(rel), {
      method: "GET", headers: { "x-agent-games-signature": "0".repeat(64) },
    }));
    record("archive: GET with bad signature -> 401", badSig.status === 401, `status=${badSig.status}`);
    const missing = await getArchive("archive/gatekeeper/does_not_exist.json");
    record("archive: GET missing record (signed) -> 404", missing.status === 404, `status=${missing.status}`);
  }

  // ---- seen-seed (pre-Vercel local era migration, 16 Nov 2026) ----
  {
    const seenMod = await import("../src/seen.mjs");
    const gkMod = await import("../src/gatekeeper.mjs");
    const seedMod = await import("../src/seen-seed.mjs");
    const GK2_TX = "0x4d84c5e935804315ab0ca81dbbacad26";
    // Memory backend (harness backend)
    const memStore = seenMod.createSeenStore({ seenBackend: "memory" });
    const memAccepted = await Promise.all(seedMod.SEED_ACCEPTED.map((tx) => memStore.hasAccepted(tx)));
    const memAll = await Promise.all(seedMod.SEED_ALL.map((tx) => memStore.hasAll(tx)));
    record("seen-seed memory: hasAccepted true for all 5 seeded accepted",
      memAccepted.every(Boolean) && memAccepted.length === 5 && (await memStore.hasAccepted(GK2_TX)) === true,
      `accepted ${memAccepted.filter(Boolean).length}/5`);
    record("seen-seed memory: hasAll true for all 19 seeded all",
      memAll.every(Boolean) && memAll.length === 19,
      `all ${memAll.filter(Boolean).length}/19`);
    // Blob backend: seed lives in the warm cache, so has* resolves true
    // without any Blob network call (cache is checked before list()).
    const blobStore = seenMod.createSeenStore({ seenBackend: "blob" });
    const blobAccepted = await Promise.all(seedMod.SEED_ACCEPTED.map((tx) => blobStore.hasAccepted(tx)));
    const blobAll = await Promise.all(seedMod.SEED_ALL.map((tx) => blobStore.hasAll(tx)));
    record("seen-seed blob: hasAccepted/hasAll true from seeded cache (5/5 + 19/19)",
      blobAccepted.every(Boolean) && blobAll.every(Boolean),
      `accepted ${blobAccepted.filter(Boolean).length}/5, all ${blobAll.filter(Boolean).length}/19`);
    // decide() on a GK2 replica: every other condition valid, proof_tx seeded
    const view = await seenMod.snapshotFor(memStore, GK2_TX);
    const cfg = { approveReasonCode: "VALID_CONDITION", fallbackRejectReasonCode: "INVALID_INPUT", seenRule: "accepted" };
    const d = gkMod.decide(mkTask({ proof_tx: GK2_TX }), view, cfg);
    record("seen-seed decide: GK2 replica (valid + seeded proof_tx) -> REJECT/PROOF_REUSED",
      d.decision === "REJECT" && d.reason_code === "PROOF_REUSED",
      `got ${d.decision}/${d.reason_code}`);
  }

  // ---- steal ----
  const poseidon = await buildPoseidon();
  const COMMITMENT = "0x" + poseidon.F.toObject(poseidon([...PARAMS, SALT])).toString(16).padStart(64, "0");
  const MATCH = "9f4e1b2a-1111-2222-3333-444455556666";
  const mkTurn = (stateOver = {}, over = {}) => ({
    protocolVersion: "v1", eventId: "steal-the-vfy", mode: "competition",
    matchId: MATCH, turn: 3,
    state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null, ...stateOver },
    strategyCommitment: { hash: COMMITMENT }, resolverVersion: "v1", nonce: "n-3",
    ...over,
  });
  const STEAL_SHAPE = ["protocolVersion", "matchId", "turn", "action", "policyProof", "agentTimestamp", "idempotencyKey"];
  const PP_SHAPE = ["circuitVersion", "publicInputsHash", "proof", "public_signals"];

  {
    const turn = mkTurn();
    const r1 = await post(base, "/agent", turn);
    const j = r1.json || {};
    const expectedHash = specHash({ commitment: COMMITMENT, matchId: MATCH, turn: 3, self: "95", opp: "105", actionCode: 2, amount: PARAMS[0] });
    let verified = false;
    if (j.policyProof && j.policyProof.proof) {
      verified = await proofMod.verifyLocal("vfy-policy", j.policyProof.public_signals, j.policyProof.proof);
    }
    const shapeOk = keysEq(j, STEAL_SHAPE) && keysEq(j.policyProof, PP_SHAPE);
    const keyOk = j.idempotencyKey === idempotencyKey(MATCH, 3);
    record("steal EXTRACT: pecker shape, hash, deterministic key, proof inside policyProof verified",
      r1.status === 200 && j.action && j.action.type === "EXTRACT" && BigInt(j.action.amount) === PARAMS[0] &&
      j.matchId === MATCH && j.turn === 3 && j.policyProof && j.policyProof.publicInputsHash === expectedHash &&
      Array.isArray(j.policyProof.public_signals) && j.policyProof.public_signals.length === 9 &&
      verified && shapeOk && keyOk && !("proof" in j) && !("public_signals" in j) && !("proofReference" in (j.policyProof || {})) && r1.sigOk,
      `hash match=${j.policyProof && j.policyProof.publicInputsHash === expectedHash}, verify=${verified}, shape=${shapeOk}, deterministicKey=${keyOk}, ${r1.ms}ms`);
    const r2 = await post(base, "/agent", turn);
    record("steal retry -> byte-identical body (deterministic idempotency)",
      r2.text === r1.text, `identical=${r2.text === r1.text}, ${r2.ms}ms`);
    const srel = `archive/steal/${MATCH}-3.json`;
    const sgot = await getArchive(srel);
    const srec = sgot.json || {};
    record("archive: steal turn archived + signed GET read-back (proof inside policyProof flagged)",
      sgot.status === 200 && srec.track === "steal" && srec.hasProof === true &&
      srec.response && srec.response.action && srec.response.action.type === "EXTRACT" &&
      !!(srec.response.policyProof && srec.response.policyProof.proof),
      `getStatus=${sgot.status}, hasProof=${srec.hasProof}`);
  }
  if (PARAMS[1] > 0n) {
    const self = (PARAMS[1] - 20n).toString();
    const r = await post(base, "/agent", mkTurn({ selfBalance: self }, { turn: 4 }));
    const j = r.json || {};
    let verified = false;
    if (j.policyProof && j.policyProof.proof) verified = await proofMod.verifyLocal("vfy-policy", j.policyProof.public_signals, j.policyProof.proof);
    record(`steal FORTIFY (self=${self} < params[1]=${PARAMS[1]}), amount omitted, proof verified`,
      r.status === 200 && j.action && j.action.type === "FORTIFY" && !("amount" in j.action) && verified,
      `got ${j.action && j.action.type}, verify=${verified}, ${r.ms}ms`);
  }
  {
    const r = await post(base, "/agent", mkTurn({ opponentBalance: "0" }, { turn: 5 }));
    const j = r.json || {};
    let verified = false;
    if (j.policyProof && j.policyProof.proof) verified = await proofMod.verifyLocal("vfy-policy", j.policyProof.public_signals, j.policyProof.proof);
    record("steal HOLD (opp=0), amount omitted, proof verified",
      r.status === 200 && j.action && j.action.type === "HOLD" && !("amount" in j.action) && verified,
      `got ${j.action && j.action.type}, verify=${verified}, ${r.ms}ms`);
  }
  {
    const r = await post(base, "/agent", { protocolVersion: "v1", eventId: "steal-the-vfy" });
    const j = r.json || {};
    record("steal malformed envelope -> fail-closed HOLD",
      r.status === 200 && j.action && j.action.type === "HOLD", `got ${j.action && j.action.type}, ${r.ms}ms`);
  }

  // ---- archive fail-open: a broken/hanging archive must never change
  // or materially delay the answer (direct handle() with rigged deps) ----
  {
    const handlerMod = await import("../src/handler.mjs");
    const cfgMod = await import("../src/config.mjs");
    const seenMod2 = await import("../src/seen.mjs");
    const logMod = await import("../src/log.mjs");
    const mkDeps = (archive, archiveTimeoutMs) => {
      const cfg = cfgMod.loadConfig({ archiveTimeoutMs });
      return { cfg, log: logMod.makeLogger("error"), store: seenMod2.createSeenStore({ seenBackend: "memory" }, logMod.makeLogger("error")), archive };
    };
    const directPost = async (deps, task) => {
      const raw = Buffer.from(JSON.stringify(task), "utf8");
      return handlerMod.handle(raw, signBody(TEST_SECRET, raw), deps);
    };
    const throwing = { backend: "broken", put: async () => { throw new Error("blob down"); }, get: async () => null };
    const rA = await directPost(mkDeps(throwing, 500), mkTask({}, { task_id: "gk_archive_failopen" }));
    const jA = JSON.parse(rA.body);
    record("archive fail-open: throwing archive store -> handler still answers APPROVE + proof",
      rA.status === 200 && jA.decision === "APPROVE" && !!jA.proof, `got ${jA.decision}/${jA.reason_code}`);
    const hanging = { backend: "hanging", put: () => new Promise(() => {}), get: async () => null };
    const tH = Date.now();
    const rB = await directPost(mkDeps(hanging, 150), mkTask({}, { task_id: "gk_archive_hang" }));
    const dtH = Date.now() - tH;
    const jB = JSON.parse(rB.body);
    record("archive fail-open: hanging archive store -> answer not blocked (timeout race)",
      rB.status === 200 && jB.decision === "APPROVE" && dtH < 5000, `got ${jB.decision}, total ${dtH}ms`);
  }

  // ---- the actual Vercel entry (Web-standard Request/Response) ----
  {
    const task = mkTask({}, { task_id: "gk_via_vercel_entry" });
    const raw = Buffer.from(JSON.stringify(task), "utf8");
    const req = new Request("http://localhost/agent", {
      method: "POST",
      headers: { "content-type": "application/json", "x-agent-games-signature": signBody(TEST_SECRET, raw) },
      body: raw,
    });
    const t = Date.now();
    const res = await api.POST(req);
    const text = await res.text();
    const ms = Date.now() - t;
    let j = null;
    try { j = JSON.parse(text); } catch (e) { /* keep null */ }
    const sigOk = res.headers.get("x-agent-games-signature") === signBody(TEST_SECRET, Buffer.from(text, "utf8"));
    record("api/agent.mjs POST export (Vercel entry) -> APPROVE + proof + signed",
      res.status === 200 && j && j.decision === "APPROVE" && !!j.proof && sigOk,
      `status=${res.status}, sigOk=${sigOk}, ${ms}ms`);
    const g = await api.GET();
    const gj = await g.json();
    record("api/agent.mjs GET export -> health", g.status === 200 && gj.ok === true && gj.configured === true, `seenBackend=${gj.seenBackend}`);
  }
} finally {
  server.close();
}

const failed = results.filter((r) => !r.ok);
console.log(`\n=== HARNESS SUMMARY: ${results.length - failed.length}/${results.length} passed in ${((Date.now() - t0) / 1000).toFixed(1)}s ===`);
if (failed.length) {
  console.log("FAILURES:");
  for (const f of failed) console.log(`  - ${f.name}: ${f.detail}`);
  process.exit(1);
}
process.exit(0);
