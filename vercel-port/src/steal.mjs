// Steal the VFY: committed policy + publicInputsHash + turn handler.
// Ported from the live agent's src/steal.js. The policy() decision list is
// IDENTICAL to the live agent / vfy-policy circuit, driven by the deployed
// STRATEGY_PARAMS from env, in strict priority order:
//   1) selfBalance < params[1] -> FORTIFY (amount 0)
//   2) opponentBalance <= params[2] || params[3]==1 -> HOLD (amount 0)
//   3) else EXTRACT with amount == params[0] EXACTLY
// Any deviation makes the turn UNPROVABLE (witness assert fails).
//
// Differences vs live, by design (Emanuel's port spec, mirroring pecker):
//   - NO Kurier anywhere: proof is generated + locally verified in the
//     handler and placed INSIDE policyProof as
//     { circuitVersion, publicInputsHash, proof, public_signals } —
//     pecker's response shape. There is no proofReference and no
//     top-level proof/public_signals on Steal responses.
//   - idempotencyKey is DETERMINISTIC per (matchId, turn) — pecker's
//     UUIDv5-shaped derivation — instead of the live agent's randomUUID
//     per response, and a proved answer is cached per (mode, matchId,
//     turn) so a platform retry returns the IDENTICAL body.
import crypto from "node:crypto";
import sha3 from "js-sha3";
import * as proofMod from "./proof.mjs";
import { buildWitness } from "./witness.mjs";
import { parseBig } from "./gatekeeper.mjs";

const { keccak256 } = sha3;

export const ACTION_CODES = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };
const ACTION_NAMES = ["HOLD", "FORTIFY", "EXTRACT"];

export function strategyParams(cfg) {
  try {
    const p = JSON.parse(cfg.strategyParamsJson || "");
    if (Array.isArray(p) && p.length === 8) return p.map((v) => BigInt(v));
  } catch (e) { /* fall through to the default below */ }
  return [10n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
}

export function policy(state, cfg) {
  const self = state.selfBalance;
  const opp = state.opponentBalance;
  const params = strategyParams(cfg);
  // Circuit decision list, strict priority (see header). params[0] is the
  // EXTRACT amount, params[1] the FORTIFY threshold, params[2]/params[3]
  // the HOLD conditions — read from the deployed STRATEGY_PARAMS so the
  // policy can never drift from the registered commitment.
  if (self < params[1]) return { type: "FORTIFY" };
  if (opp <= params[2] || params[3] === 1n) return { type: "HOLD" };
  return { type: "EXTRACT", amount: params[0] };
}

export function bytes32(v) {
  let x = BigInt(v);
  if (x < 0n || x >= (1n << 256n)) throw new Error("value out of 32-byte range");
  const hex = x.toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

// SPEC §5.4 — field order is critical:
// commitment, matchId (dashes stripped), turn, selfBalance, opponentBalance,
// action code, amount (0 for HOLD/FORTIFY), circuitVersion (v1 -> 1).
// commitmentOverride lets the fail-closed path hash with the zero
// commitment when the envelope carries none.
export function publicInputsHash(envelope, actionType, amount, commitmentOverride) {
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

// UUIDv5-shaped (version + variant bits set), deterministic per
// (matchId, turn) — pecker's derivation. A retry reuses the key; a new
// turn never does.
export function idempotencyKey(matchId, turn) {
  const b = crypto.createHash("sha256").update(`${matchId}:${turn}`).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x50;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// Proved answers cached per (mode, matchId, turn): a platform retry gets
// the identical body (pecker semantics). In-memory only — a cold start
// recomputes the same deterministic response except agentTimestamp.
const answers = new Map();

function buildResponse(envelope, action, hash, proved) {
  const resp = {
    protocolVersion: "v1",
    matchId: envelope && envelope.matchId,
    turn: envelope && envelope.turn,
    action: action.type === "EXTRACT"
      ? { type: "EXTRACT", amount: Number(action.amount) }
      : { type: action.type }, // amount omitted entirely for HOLD/FORTIFY (SPEC §5.7)
    policyProof: { circuitVersion: "v1", publicInputsHash: hash },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: envelope && envelope.matchId !== undefined
      ? idempotencyKey(envelope.matchId, envelope.turn)
      : crypto.randomUUID(),
  };
  if (proved) {
    resp.policyProof.proof = proved.proof;
    resp.policyProof.public_signals = proved.publicSignals;
  }
  return resp;
}

export function holdFallback(envelope, cfg, log, why) {
  if (log) log("warn", `steal fail-closed HOLD: ${why}`);
  let hash;
  try {
    hash = publicInputsHash(envelope, "HOLD", 0);
  } catch (e) {
    // No commitment in the envelope — fall back to the zero commitment so
    // the field is still a string. Only a structurally broken envelope
    // (no matchId/state to hash) leaves the field unset.
    try { hash = publicInputsHash(envelope, "HOLD", 0, 0n); }
    catch (e2) { /* envelope too broken to hash — policyProof stays minimal */ }
  }
  const resp = buildResponse(envelope, { type: "HOLD" }, hash, null);
  if (hash === undefined) delete resp.policyProof.publicInputsHash;
  return resp;
}

export async function handleStealTurn(envelope, deps) {
  const { cfg, log } = deps;
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

    const cacheKey = `${envelope.mode}:${envelope.matchId}:${state.turn}`;
    const hit = answers.get(cacheKey);
    if (hit) {
      log("info", `steal match=${envelope.matchId} turn=${state.turn} -> cached answer (retry)`);
      return hit;
    }

    const action = policy(state, cfg);
    const amount = action.type === "EXTRACT" ? action.amount : 0n;
    const hash = publicInputsHash(envelope, action.type, amount);

    // --- policy proof (best effort inside the turn budget) ---
    if (!cfg.strategySalt || !cfg.strategyParamsJson) {
      log("warn", "steal: STRATEGY_SALT/STRATEGY_PARAMS not set — responding without proof");
      return buildResponse(envelope, action, hash, null);
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
      const { proof, publicSignals, ms } = await proofMod.fullProve("vfy-policy", input, proveBudget);
      const verified = await proofMod.verifyLocal("vfy-policy", publicSignals, proof);
      if (!verified) throw new Error("steal proof FAILED local verification");
      const resp = buildResponse(envelope, action, hash, { proof, publicSignals });
      answers.set(cacheKey, resp);
      log("info", `steal match=${envelope.matchId} turn=${state.turn} proof in ${ms}ms (local verify: true)`);
      log("info", `steal match=${envelope.matchId} turn=${state.turn} -> ${action.type}${action.type === "EXTRACT" ? " " + action.amount : ""} in ${elapsed()}ms`);
      return resp;
    } catch (e) {
      // Proof pipeline failure (e.g. envelope commitment != Poseidon(env
      // params, salt)). STEAL_PROOF_REQUIRED=true turns this into a
      // strict HOLD; default keeps the policy action without a proof
      // (the platform scores a proof-less turn as HOLD either way).
      log("error", `steal proof pipeline failed (${e.code || e.message})`);
      if (cfg.stealProofRequired) return holdFallback(envelope, cfg, log, "proof required but pipeline failed");
      return buildResponse(envelope, action, hash, null);
    }
  } catch (e) {
    return holdFallback(envelope, cfg, log, e.message);
  }
}

export { ACTION_NAMES };
