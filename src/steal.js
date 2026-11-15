"use strict";
// Steal the VFY: committed policy + publicInputsHash + turn handler.
// Policy = EXACTLY the vfy-policy circuit's decision list
// (WITNESS-NOTES.md, verified by probe: lines ~140/~149), driven by the
// deployed STRATEGY_PARAMS from env — in strict priority order:
//   1) selfBalance < params[1] -> FORTIFY (amount 0). Wins over every
//      other branch, even opponentBalance == 0.
//   2) opponentBalance <= params[2] || params[3]==1 -> HOLD (amount 0).
//   3) else EXTRACT with amount == params[0] EXACTLY (NOT capped by the
//      opponent balance — the resolver caps the actual take; the circuit
//      rejects amount != params[0] at its line 149).
// With the deployed params [10,70,0,0,0,0,0,0] this is: FORTIFY whenever
// selfBalance < 70, HOLD only at opponentBalance == 0, else EXTRACT 10.
// Any deviation from this list makes the turn UNPROVABLE: the witness
// assert fails, the proof pipeline errors, and the turn goes out without
// a proof (platform: invalid proof, -2, HOLD substitute). The old
// EXTRACT-always policy was correct only for params[1] = 0; it silently
// broke every turn with selfBalance < 70 after the [10,70] redeploy
// (see evaluation Round 01, 14 Nov 2026). There is no turn-based branch
// in the circuit — endgame FORTIFY conditions must never be added here,
// they cannot be proven.
//
// Schema fixes made permanent 13 Nov 2026 (post-practice; both were
// proven against the live platform in practice session 2):
//   (a) idempotencyKey is a PLAIN UUID — the platform rejects the old
//       "matchId:turn:uuid" composite with "idempotencyKey: Invalid UUID".
//   (b) policyProof.publicInputsHash is ALWAYS a string — including the
//       fail-closed HOLD path. When the envelope carries no strategy
//       commitment (practice envelopes don't), the hash is computed with
//       the zero commitment, which is exactly what the platform
//       recomputed and VERIFIED in practice. An absent field is rejected
//       with "publicInputsHash: expected string, received undefined".
const crypto = require("crypto");
const { keccak256 } = require("js-sha3");
const proofMod = require("./proof");
const { submitTracked, quickSubmitRef } = require("./kurier");
const { buildWitness } = require("./witness");
const { parseBig } = require("./gatekeeper");

const ACTION_CODES = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

function strategyParams(cfg) {
  try {
    const p = JSON.parse(cfg.strategyParamsJson || "");
    if (Array.isArray(p) && p.length === 8) return p.map((v) => BigInt(v));
  } catch (e) { /* fall through to the default below */ }
  return [10n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
}

function policy(state, cfg) {
  const self = state.selfBalance;
  const opp = state.opponentBalance;
  const params = strategyParams(cfg);
  // Circuit decision list, strict priority (see header). params[0] is the
  // EXTRACT amount, params[1] the FORTIFY threshold, params[2]/params[3]
  // the HOLD conditions — all read from the deployed STRATEGY_PARAMS so
  // the policy can never drift from the registered commitment.
  if (self < params[1]) return { type: "FORTIFY" };
  if (opp <= params[2] || params[3] === 1n) return { type: "HOLD" };
  return { type: "EXTRACT", amount: params[0] };
}

function bytes32(v) {
  let x = BigInt(v);
  if (x < 0n || x >= (1n << 256n)) throw new Error("value out of 32-byte range");
  const hex = x.toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

// SPEC §5.4 — field order is critical:
// commitment, matchId (dashes stripped), turn, selfBalance, opponentBalance,
// action code, amount (0 for HOLD/FORTIFY), circuitVersion (v1 -> 1).
// commitmentOverride lets the fail-closed path hash with the zero
// commitment when the envelope carries none (see header note (b)).
function publicInputsHash(envelope, actionType, amount, commitmentOverride) {
  let commitment = commitmentOverride;
  if (commitment === undefined) {
    commitment = envelope && envelope.strategyCommitment && envelope.strategyCommitment.hash;
  }
  if (commitment === undefined || commitment === null) {
    throw new Error("envelope.strategyCommitment.hash missing");
  }
  const fields = [
    BigInt(commitment),
    BigInt("0x" + String(envelope.matchId).replace(/-/g, "")),
    BigInt(envelope.turn),
    parseBig(envelope.state.selfBalance),
    parseBig(envelope.state.opponentBalance),
    BigInt(ACTION_CODES[actionType]),
    BigInt(amount || 0),
    1n,
  ];
  return "0x" + keccak256(Buffer.concat(fields.map(bytes32)));
}

function baseResponse(envelope) {
  return {
    matchId: envelope && envelope.matchId,
    turn: envelope && envelope.turn,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: crypto.randomUUID(),
  };
}

function holdFallback(envelope, cfg, log, why) {
  if (log) log("warn", `steal fail-closed HOLD: ${why}`);
  const resp = baseResponse(envelope);
  resp.action = { type: "HOLD" };
  resp.policyProof = { circuitVersion: "v1" };
  try {
    resp.policyProof.publicInputsHash = publicInputsHash(envelope, "HOLD", 0);
  } catch (e) {
    // No commitment in the envelope — fall back to the zero commitment so
    // the field is still a string (header note (b)). Only a structurally
    // broken envelope (no matchId/state to hash) leaves the field unset.
    try {
      resp.policyProof.publicInputsHash = publicInputsHash(envelope, "HOLD", 0, 0n);
    } catch (e2) { /* envelope too broken to hash — policyProof stays minimal */ }
  }
  return resp;
}

async function handleStealTurn(envelope, deps) {
  const { cfg, kurier, log } = deps;
  const t0 = Date.now();
  const elapsed = () => Date.now() - t0;
  try {
    if (!envelope || typeof envelope !== "object") throw new Error("envelope not an object");
    if (typeof envelope.matchId !== "string" || envelope.matchId === "") throw new Error("matchId missing");
    if (!envelope.state || typeof envelope.state !== "object") throw new Error("state missing");
    const state = {
      turn: Number(envelope.turn),
      selfBalance: parseBig(envelope.state.selfBalance),
      opponentBalance: parseBig(envelope.state.opponentBalance),
    };
    if (!Number.isInteger(state.turn)) throw new Error("turn not an integer");

    const action = policy(state, cfg);
    const amount = action.type === "EXTRACT" ? action.amount : 0n;
    const hash = publicInputsHash(envelope, action.type, amount);

    const resp = baseResponse(envelope);
    resp.action = action.type === "EXTRACT"
      ? { type: "EXTRACT", amount: Number(action.amount) }
      : { type: action.type }; // amount omitted entirely for HOLD/FORTIFY (SPEC §5.7)
    resp.policyProof = { circuitVersion: "v1", publicInputsHash: hash };

    // --- policy proof (best effort inside the turn budget) ---
    if (!cfg.strategySalt || !cfg.strategyParamsJson) {
      log("warn", "steal: STRATEGY_SALT/STRATEGY_PARAMS not set — responding without proof");
      return resp;
    }
    try {
      const witnessCtx = {
        envelope,
        actionCode: String(ACTION_CODES[action.type]),
        actionAmount: String(amount),
        env: { STRATEGY_SALT: cfg.strategySalt, STRATEGY_PARAMS: cfg.strategyParamsJson },
      };
      const { input } = buildWitness("steal", witnessCtx);
      const proveBudget = Math.min(cfg.proofTimeoutMs, Math.max(1000, cfg.stealRespondByMs - elapsed()));
      const { proof, publicSignals, ms } = await proofMod.fullProve(cfg, "vfy-policy", input, proveBudget);
      resp.proof = proof;
      resp.public_signals = publicSignals;
      log("info", `steal match=${envelope.matchId} turn=${state.turn} proof in ${ms}ms`);
      if (kurier && kurier.enabled) {
        // Background submission (same decoupling as gatekeeper.js):
        // finalization is tracked with [kurier-bg] logging and NEVER
        // awaited here. proofReference is filled ONLY from a reference
        // carried by the fast submit response itself (raced against
        // cfg.kurierSubmitRaceMs, target < 2s); previously it was taken
        // from the finalized job status after waiting up to ~24s — and
        // in R02 every submission failed KURIER_HTTP, so the field was
        // never set in scored play anyway.
        const submitPromise = submitTracked(kurier, log, `steal match=${envelope.matchId} turn=${state.turn}`, { vkHash: cfg.stealVkHash, proof, publicSignals });
        const ref = await quickSubmitRef(submitPromise, cfg.kurierSubmitRaceMs);
        if (ref) resp.policyProof.proofReference = ref;
      }
    } catch (e) {
      // Proof pipeline failure (the vfy-policy semantics are SOLVED — see
      // WITNESS-NOTES.md — so this is now a genuine pipeline/env failure,
      // e.g. envelope commitment != Poseidon(env params, salt)).
      // STEAL_PROOF_REQUIRED=true turns this into a strict HOLD; default
      // keeps the policy action (the platform scores a proof-less turn as
      // HOLD either way) so the eval can see it.
      log("error", `steal proof pipeline failed (${e.code || e.message})`);
      if (cfg.stealProofRequired) return holdFallback(envelope, cfg, log, "proof required but pipeline failed");
      delete resp.proof;
      delete resp.public_signals;
    }
    log("info", `steal match=${envelope.matchId} turn=${state.turn} -> ${action.type}${action.type === "EXTRACT" ? " " + action.amount : ""} in ${elapsed()}ms`);
    return resp;
  } catch (e) {
    return holdFallback(envelope, cfg, log, e.message);
  }
}

module.exports = { policy, publicInputsHash, handleStealTurn, ACTION_CODES, bytes32 };
