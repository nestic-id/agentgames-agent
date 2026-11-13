"use strict";
// Steal the VFY: committed policy + publicInputsHash + turn handler.
// Policy = STEAL-STRATEGY.md's shipped policy:
//   EXTRACT every turn (amount = min(cap, opponent balance));
//   HOLD only when opponent balance == 0;
//   FORTIFY endgame branches exist ONLY behind cfg.fortifyBlocks
//   (FORTIFY_BLOCKS env, default false — the strategy analysis shows they
//   never improved an outcome across the simulation grid).
const crypto = require("crypto");
const { keccak256 } = require("js-sha3");
const proofMod = require("./proof");
const { buildWitness } = require("./witness");
const { parseBig } = require("./gatekeeper");

const ACTION_CODES = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

function policy(state, cfg) {
  const turn = state.turn;
  const self = state.selfBalance;
  const opp = state.opponentBalance;
  if (opp <= 0n) return { type: "HOLD" };
  if (cfg.fortifyBlocks) {
    const E = BigInt(cfg.stealExtractCap);
    const C = BigInt(cfg.stealFortifyCost);
    const minE = self < E ? self : E;
    if (turn === 20 && self > opp && C < minE) return { type: "FORTIFY" };
    if (turn >= 18 && self > opp && self < E && C < self) return { type: "FORTIFY" };
  }
  const cap = BigInt(cfg.stealExtractCap);
  const amount = opp < cap ? opp : cap;
  return { type: "EXTRACT", amount };
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
function publicInputsHash(envelope, actionType, amount) {
  const commitment = envelope.strategyCommitment && envelope.strategyCommitment.hash;
  if (commitment === undefined) throw new Error("envelope.strategyCommitment.hash missing");
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
    idempotencyKey: `${envelope && envelope.matchId}:${envelope && envelope.turn}:${crypto.randomUUID()}`,
  };
}

function holdFallback(envelope, cfg, log, why) {
  if (log) log("warn", `steal fail-closed HOLD: ${why}`);
  const resp = baseResponse(envelope);
  resp.action = { type: "HOLD" };
  resp.policyProof = { circuitVersion: "v1" };
  try {
    resp.policyProof.publicInputsHash = publicInputsHash(envelope, "HOLD", 0);
  } catch (e) { /* envelope too broken to hash — policyProof stays minimal */ }
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
        const waitBudget = Math.min(cfg.kurierWaitBudgetMs, Math.max(0, cfg.stealRespondByMs - elapsed() - 500));
        if (waitBudget > 0) {
          try {
            const { jobId } = await kurier.submitProof({ vkHash: cfg.stealVkHash, proof, publicSignals });
            const res = await kurier.waitFinalized(jobId, waitBudget);
            if (res.ref) resp.policyProof.proofReference = res.ref;
            log("info", `steal match=${envelope.matchId} turn=${state.turn} kurier job=${jobId} status=${res.status}`);
          } catch (e) {
            log("warn", `steal kurier failed (${e.code || e.message}) — local proof only`);
          }
        }
      }
    } catch (e) {
      // Proof pipeline failure (incl. the currently-unresolved vfy-policy
      // asserts, see WITNESS-NOTES.md). STEAL_PROOF_REQUIRED=true turns this
      // into a strict HOLD; default keeps the policy action (the platform
      // scores a proof-less turn as HOLD either way) so the eval can see it.
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
