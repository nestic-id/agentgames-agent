#!/usr/bin/env node
"use strict";
// sk56 EVAL harness — scored, not a smoke test.
// Boots the real HTTP service on an ephemeral port with .env.test values
// and replays fabricated envelopes end-to-end (HMAC, routing, decision
// engine, proof generation, seen-set persistence).
// Prints a Gatekeeper accuracy scorecard per trap type + Steal behavior
// summary. Exit code 1 if any case fails.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { keccak256 } = require("js-sha3");

// --- load .env.test into process.env BEFORE config ---
const envTest = fs.readFileSync(path.join(__dirname, "..", ".env.test"), "utf8");
for (const line of envTest.split(/\r?\n/)) {
  const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
  if (m && !line.trim().startsWith("#")) process.env[m[1]] = m[2];
}
const TEST_SECRET = process.env.AGENT_GAMES_HMAC_SECRET;

const { loadConfig } = require("../src/config");
const { createApp } = require("../src/server");
const { makeLogger } = require("../src/log");
const proofMod = require("../src/proof");

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
  const res = await fetch(base + route, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: raw,
  });
  const text = await res.text();
  const respSig = res.headers.get("x-agent-games-signature");
  const sigOk = respSig === signBody(TEST_SECRET, Buffer.from(text, "utf8"));
  let json = null;
  try { json = JSON.parse(text); } catch (e) { /* keep null */ }
  return { status: res.status, json, sigOk };
}

// Independent publicInputsHash implementation straight from SPEC §5.4,
// used to cross-check the service's hash byte-for-byte.
function specHash({ commitment, matchId, turn, self, opp, actionCode, amount }) {
  const f = (v) => Buffer.from(BigInt(v).toString(16).padStart(64, "0"), "hex");
  const pre = Buffer.concat([
    f(commitment), f("0x" + matchId.replace(/-/g, "")), f(turn), f(self), f(opp),
    f(actionCode), f(amount), f(1),
  ]);
  return "0x" + keccak256(pre);
}

(async () => {
  const t0 = Date.now();
  // Keccak sanity: js-sha3 must be real Keccak-256 (empty-string vector).
  const emptyK = keccak256("");
  if (emptyK !== "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") {
    console.error("keccak256 implementation mismatch on empty-string vector");
    process.exit(1);
  }

  const tmpData = fs.mkdtempSync(path.join(os.tmpdir(), "agentgames-eval-"));
  const cfg = loadConfig({ port: 0, host: "127.0.0.1", dataDir: tmpData, kurierApiKey: "" });
  const log = makeLogger("error");
  const { server } = createApp(cfg, log);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  console.log(`eval server on ${base} (data dir ${tmpData})\n`);

  try {
    // ---- transport / protocol ----
    {
      const res = await fetch(base + "/health");
      const j = await res.json();
      record("health endpoint", res.status === 200 && j.ok === true);
    }
    {
      const r = await post(base, "/agent/gatekeeper", { type: "agent-games.preflight.v1", agent_id: "agt_eval", nonce: "n1" });
      record("preflight -> {ok:true, protocolVersion:'v1'} + signed",
        r.status === 200 && r.json && r.json.ok === true && r.json.protocolVersion === "v1" && r.sigOk,
        `sigOk=${r.sigOk}`);
    }
    {
      const r = await post(base, "/agent/gatekeeper", { type: "agent-games.preflight.v1" }, { badSig: true });
      record("bad HMAC -> 401", r.status === 401, `status=${r.status}`);
    }

    // ---- gatekeeper decision eval (scorecard) ----
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

    const scorecard = {}; // trapType -> {correct, total}
    async function gkCase(type, task, expectDecision, expectCode, { expectProof = null } = {}) {
      const r = await post(base, "/agent/gatekeeper", task);
      const got = r.json || {};
      let ok = r.status === 200 && got.decision === expectDecision && got.reason_code === expectCode && r.sigOk;
      let detail = `got ${got.decision}/${got.reason_code}`;
      if (expectProof === true) {
        const hasProof = !!got.proof && Array.isArray(got.public_signals);
        ok = ok && hasProof;
        detail += hasProof ? `, proof+${got.public_signals.length} signals` : ", NO PROOF";
        if (hasProof && expectDecision === "APPROVE") {
          const v = await proofMod.verifyLocal(cfg, "gatekeeper", got.public_signals, got.proof, log);
          ok = ok && v === true;
          detail += `, localVerify=${v}`;
        }
      }
      if (expectProof === false) {
        const noProof = !got.proof && !got.public_signals;
        ok = ok && noProof;
        detail += noProof ? ", no proof (correct)" : ", proof present (WRONG)";
      }
      scorecard[type] = scorecard[type] || { correct: 0, total: 0 };
      scorecard[type].total++;
      if (ok) scorecard[type].correct++;
      record(`gatekeeper[${type}]`, ok, detail);
      return r;
    }

    // (a) SPEC §4.1 sample envelope, verbatim abbreviated values.
    await gkCase("VK_SUBSTITUTION (SPEC sample)", {
      type: "agent-games.proof-gatekeeper.v1", task_id: "gk_8d31_sample", mode: "competition",
      input: {
        registered_vk: "0x7d...91", proof_vk: "0x13...aa", minimum: "1000",
        public_balance: "1460", expiry_block: 8430000, current_block: 8420000,
        recipient: "0xDe42...9f01", condition_recipient: "0xDe42...9f01",
        amount: "500", max_transfer: "1000", proof_tx: "0xa8...2c",
      },
    }, "REJECT", "VK_SUBSTITUTION");

    // (b) valid -> approve with verifiable proof
    await gkCase("VALID_CONDITION", mkTask(), "APPROVE", "VALID_CONDITION", { expectProof: true });
    // (c) one fabricated case per trap type
    await gkCase("VK_SUBSTITUTION", mkTask({ proof_vk: VK2 }), "REJECT", "VK_SUBSTITUTION", { expectProof: true });
    await gkCase("THRESHOLD_MISMATCH", mkTask({ public_balance: "999" }), "REJECT", "THRESHOLD_MISMATCH", { expectProof: true });
    await gkCase("EXPIRED_CONDITION", mkTask({ current_block: 8430001 }), "REJECT", "EXPIRED_CONDITION", { expectProof: true });
    await gkCase("RECIPIENT_MISMATCH", mkTask({ recipient: ADDR2 }), "REJECT", "RECIPIENT_MISMATCH", { expectProof: true });
    await gkCase("AMOUNT_OVERFLOW", mkTask({ amount: "1001" }), "REJECT", "AMOUNT_OVERFLOW", { expectProof: true });
    // PROOF_REUSED: same proof_tx twice — first approves, second must reject without proof.
    const reusedTx = freshTx();
    await gkCase("VALID_CONDITION (reuse setup)", mkTask({ proof_tx: reusedTx }), "APPROVE", "VALID_CONDITION", { expectProof: true });
    await gkCase("PROOF_REUSED", mkTask({ proof_tx: reusedTx }), "REJECT", "PROOF_REUSED", { expectProof: false });
    // malformed envelope -> fail-closed reject
    {
      const r = await post(base, "/agent/gatekeeper", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_bad" });
      record("gatekeeper malformed envelope -> fail-closed REJECT",
        r.status === 200 && r.json && r.json.decision === "REJECT", `got ${r.json && r.json.decision}/${r.json && r.json.reason_code}`);
    }

    console.log("\n--- Gatekeeper decision scorecard ---");
    let totC = 0, totT = 0;
    for (const [type, s] of Object.entries(scorecard)) {
      console.log(`  ${type.padEnd(34)} ${s.correct}/${s.total}`);
      totC += s.correct; totT += s.total;
    }
    console.log(`  ${"TOTAL".padEnd(34)} ${totC}/${totT}`);

    // ---- steal eval ----
    // Commitment for the .env.test strategy (params [10,70,0,0,0,0,0,0],
    // salt 7): computed, not hardcoded, so the circuit's line-72 assert
    // (commitment == Poseidon(params..., salt)) holds and REAL Groth16
    // proofs are generated + verified in this eval. .env.test MUST track
    // the deployed STRATEGY_PARAMS or these proofs fail exactly like the
    // platform's would.
    const { buildPoseidon } = require("circomlibjs");
    const poseidon = await buildPoseidon();
    const COMMITMENT = "0x" + poseidon.F.toObject(poseidon([[10n, 70n, 0n, 0n, 0n, 0n, 0n, 0n], 7n].flat())).toString(16).padStart(64, "0");
    const mkTurn = (stateOver = {}) => ({
      protocolVersion: "v1", eventId: "steal-the-vfy", mode: "competition",
      matchId: "9f4e1b2a-1111-2222-3333-444455556666", turn: 3,
      state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null, ...stateOver },
      strategyCommitment: { hash: COMMITMENT }, resolverVersion: "v1", nonce: "n-3",
    });
    {
      const turn = mkTurn();
      const r1 = await post(base, "/agent/steal", turn);
      const j = r1.json || {};
      const expectedHash = specHash({ commitment: COMMITMENT, matchId: turn.matchId, turn: 3, self: "95", opp: "105", actionCode: 2, amount: 10 });
      let proofVerified = false;
      if (j.proof && Array.isArray(j.public_signals)) {
        proofVerified = await proofMod.verifyLocal(cfg, "vfy-policy", j.public_signals, j.proof, log);
      }
      record("steal turn (opp=105) -> EXTRACT 10, echo + hash + key + REAL proof verified vs VK",
        r1.status === 200 && j.action && j.action.type === "EXTRACT" && j.action.amount === 10 &&
        j.matchId === turn.matchId && j.turn === 3 &&
        j.policyProof && j.policyProof.publicInputsHash === expectedHash &&
        typeof j.idempotencyKey === "string" &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(j.idempotencyKey) && r1.sigOk &&
        !!j.proof && Array.isArray(j.public_signals) && j.public_signals.length === 9 && proofVerified,
        `hash match=${j.policyProof && j.policyProof.publicInputsHash === expectedHash}, key=${j.idempotencyKey}, proof attached=${!!j.proof}, vk verify=${proofVerified}`);
      const r2 = await post(base, "/agent/steal", turn);
      record("steal idempotencyKey unique per response",
        !!(r2.json && r2.json.idempotencyKey && r2.json.idempotencyKey !== j.idempotencyKey));
    }
    {
      const r = await post(base, "/agent/steal", mkTurn({ opponentBalance: "0" }));
      const j = r.json || {};
      let holdVerified = false;
      if (j.proof && Array.isArray(j.public_signals)) {
        holdVerified = await proofMod.verifyLocal(cfg, "vfy-policy", j.public_signals, j.proof, log);
      }
      record("steal turn (opp=0) -> HOLD, amount field omitted, REAL proof verified",
        r.status === 200 && j.action && j.action.type === "HOLD" && !("amount" in j.action) &&
        !!j.proof && holdVerified,
        `got ${j.action && j.action.type}, proof attached=${!!j.proof}, vk verify=${holdVerified}`);
    }
    {
      const r = await post(base, "/agent/steal", mkTurn({ opponentBalance: "4" }));
      const j = r.json || {};
      record("steal turn (opp=4) -> EXTRACT amount == params[0] (10), NOT capped by balance",
        r.status === 200 && j.action && j.action.type === "EXTRACT" && j.action.amount === 10 && !!j.proof,
        `got ${j.action && j.action.type} ${j.action && j.action.amount}, proof attached=${!!j.proof}`);
    }
    {
      // params[1]=70: selfBalance < 70 MUST be FORTIFY (circuit branch 1,
      // wins over every other branch) with a REAL proof verified vs VK.
      // Regression: the old EXTRACT-always policy made this turn
      // unprovable (witness assert fail -> no proof -> platform -2).
      const r = await post(base, "/agent/steal", mkTurn({ selfBalance: "50" }));
      const j = r.json || {};
      let verified = false;
      if (j.proof && Array.isArray(j.public_signals)) {
        verified = await proofMod.verifyLocal(cfg, "vfy-policy", j.public_signals, j.proof, log);
      }
      record("steal turn (self=50 < 70) -> FORTIFY, REAL proof verified",
        r.status === 200 && j.action && j.action.type === "FORTIFY" && !("amount" in j.action) &&
        !!j.proof && verified,
        `got ${j.action && j.action.type}, proof attached=${!!j.proof}, vk verify=${verified}`);
    }
    {
      // Branch 1 beats branch 2: self < 70 fortifies even at opp == 0.
      const r = await post(base, "/agent/steal", mkTurn({ selfBalance: "69", opponentBalance: "0" }));
      const j = r.json || {};
      let verified = false;
      if (j.proof && Array.isArray(j.public_signals)) {
        verified = await proofMod.verifyLocal(cfg, "vfy-policy", j.public_signals, j.proof, log);
      }
      record("steal turn (self=69, opp=0) -> FORTIFY, not HOLD",
        r.status === 200 && j.action && j.action.type === "FORTIFY" && !!j.proof && verified,
        `got ${j.action && j.action.type}, vk verify=${verified}`);
    }
    {
      // Boundary is strict <: self == 70 still extracts.
      const r = await post(base, "/agent/steal", mkTurn({ selfBalance: "70" }));
      const j = r.json || {};
      record("steal turn (self=70) -> EXTRACT 10 (boundary, strict <)",
        r.status === 200 && j.action && j.action.type === "EXTRACT" && j.action.amount === 10 && !!j.proof,
        `got ${j.action && j.action.type} ${j.action && j.action.amount}`);
    }
    {
      const t = mkTurn();
      delete t.strategyCommitment; // practice-shaped envelope: no commitment field
      const r = await post(base, "/agent/steal", t);
      const j = r.json || {};
      record("steal envelope without commitment -> fail-closed HOLD, hash still a string, key is plain UUID",
        r.status === 200 && j.action && j.action.type === "HOLD" &&
        j.policyProof && typeof j.policyProof.publicInputsHash === "string" &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(j.idempotencyKey || ""),
        `hash type=${j.policyProof && typeof j.policyProof.publicInputsHash}, key=${j.idempotencyKey}`);
    }
    {
      const r = await post(base, "/agent/steal", { protocolVersion: "v1", eventId: "steal-the-vfy" });
      const j = r.json || {};
      record("steal malformed envelope -> fail-closed HOLD",
        r.status === 200 && j.action && j.action.type === "HOLD", `got ${j.action && j.action.type}`);
    }

    // ---- kurier decoupling (regression, 15 Nov 2026) ----
    // Practice session 3: handlers AWAITED Kurier Finalized before
    // responding (20–31s vs the 15s practice deadline -> 0/7 delivery
    // timeouts). A second app runs with a FAKE Kurier client patched
    // onto deps: submissions/finalization are slow or hanging, and the
    // handlers must still respond fast while the background tracker
    // ([kurier-bg] logs) completes the submission on its own.
    {
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const waitFor = async (fn, timeoutMs) => {
        const s = Date.now();
        while (Date.now() - s < timeoutMs) { if (fn()) return true; await sleep(50); }
        return fn();
      };
      const tmpData2 = fs.mkdtempSync(path.join(os.tmpdir(), "agentgames-kurier-"));
      const cfg2 = loadConfig({ port: 0, host: "127.0.0.1", dataDir: tmpData2, kurierApiKey: "test-key", kurierSubmitRaceMs: 800 });
      const bgLines = [];
      const log2 = (lvl, msg) => { bgLines.push(String(msg)); };
      const app2 = createApp(cfg2, log2);
      const fake = { submitDelay: 0, finDelay: 0, raw: {}, submitCalls: [], finCalls: [] };
      app2.deps.kurier.submitProof = async (args) => {
        fake.submitCalls.push(args);
        await sleep(fake.submitDelay);
        return { jobId: "job-fake-1", raw: fake.raw };
      };
      app2.deps.kurier.waitFinalized = async (jobId, budget) => {
        fake.finCalls.push({ jobId, budget });
        await sleep(fake.finDelay);
        return { status: "Finalized", ref: "0xrefbg", jobId };
      };
      await new Promise((r) => app2.server.listen(0, "127.0.0.1", r));
      const base2 = `http://127.0.0.1:${app2.server.address().port}`;
      try {
        // (A) gatekeeper: submit takes 600ms, finalization 150ms — the
        // response must land on proof time alone, and the background
        // tracker must still submit once and log Finalized.
        fake.submitDelay = 600; fake.finDelay = 150; fake.raw = { jobId: "job-fake-1" };
        fake.submitCalls.length = 0; fake.finCalls.length = 0;
        let tA = Date.now();
        const rA = await post(base2, "/agent/gatekeeper", mkTask({}, { task_id: "gk_kurier_bg" }));
        const durA = Date.now() - tA;
        const bgDoneA = await waitFor(() => bgLines.some((l) => l.includes("[kurier-bg]") && l.includes("status=Finalized")), 3000);
        record("kurier decoupled: gatekeeper responds without waiting for Kurier, background tracks to Finalized",
          rA.status === 200 && rA.json && rA.json.decision === "APPROVE" && !!rA.json.proof && durA < 3000 &&
          fake.submitCalls.length === 1 && fake.submitCalls[0].vkHash === cfg2.gatekeeperVkHash &&
          fake.finCalls.length === 1 && fake.finCalls[0].budget === cfg2.kurierWaitBudgetMs && bgDoneA,
          `dur=${durA}ms, submits=${fake.submitCalls.length}, finBudget=${fake.finCalls[0] && fake.finCalls[0].budget}, bgFinalizedLogged=${bgDoneA}`);

        // (B) gatekeeper: finalization HANGS for 60s — response must
        // still be fast (this is the exact session-3 failure shape).
        fake.submitDelay = 10; fake.finDelay = 60000;
        let tB = Date.now();
        const rB = await post(base2, "/agent/gatekeeper", mkTask({}, { task_id: "gk_kurier_hang" }));
        const durB = Date.now() - tB;
        record("kurier decoupled: gatekeeper fast even when Kurier finalization hangs 60s",
          rB.status === 200 && rB.json && rB.json.decision === "APPROVE" && !!rB.json.proof && durB < 3000,
          `dur=${durB}ms`);

        // (C) steal: the submit response itself carries a reference ->
        // proofReference is filled from that fast submit call.
        fake.submitDelay = 50; fake.finDelay = 100; fake.raw = { jobId: "job-fake-1", txHash: "0xdeadbeef" };
        let tC = Date.now();
        const rC = await post(base2, "/agent/steal", mkTurn());
        const durC = Date.now() - tC;
        const jC = rC.json || {};
        record("kurier decoupled: steal proofReference harvested from fast submit response",
          rC.status === 200 && jC.action && jC.action.type === "EXTRACT" && !!jC.proof &&
          jC.policyProof && jC.policyProof.proofReference === "0xdeadbeef" && durC < 3000,
          `dur=${durC}ms, proofReference=${jC.policyProof && jC.policyProof.proofReference}`);

        // (D) steal: submit slower than the race bound -> response goes
        // out without proofReference and without waiting for the submit.
        fake.submitDelay = 5000; fake.raw = {};
        let tD = Date.now();
        const rD = await post(base2, "/agent/steal", mkTurn());
        const durD = Date.now() - tD;
        const jD = rD.json || {};
        record("kurier decoupled: steal does not wait for a slow Kurier submit",
          rD.status === 200 && jD.action && jD.action.type === "EXTRACT" && !!jD.proof &&
          !(jD.policyProof && jD.policyProof.proofReference) && durD < 3000,
          `dur=${durD}ms, proofReference=${jD.policyProof && jD.policyProof.proofReference}`);
      } finally {
        app2.server.close();
      }
    }
  } finally {
    server.close();
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n=== EVAL SUMMARY: ${results.length - failed.length}/${results.length} passed in ${((Date.now() - t0) / 1000).toFixed(1)}s ===`);
  if (failed.length) {
    console.log("FAILURES:");
    for (const f of failed) console.log(`  - ${f.name}: ${f.detail}`);
    process.exit(1);
  }
  process.exit(0);
})().catch((e) => { console.error("eval crashed:", e); process.exit(1); });
