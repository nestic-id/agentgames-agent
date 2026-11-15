// Proof Gatekeeper: decision engine (pure, fail-closed) + task handler.
// Ported from the live agent's src/gatekeeper.js. The decide() body is
// IDENTICAL to the live agent — same check order (VK -> threshold ->
// proof-reuse -> expiry -> recipient -> amount), same reason_codes, same
// expiry semantics (current_block > expiry_block) — only the store is a
// synchronous snapshot (see seen.mjs) because the durable backends are
// async on serverless.
//
// Differences vs live, by design (Emanuel's port spec, mirroring pecker):
//   - NO Kurier anywhere: the Groth16 proof is generated locally, verified
//     locally, and embedded in the response.
//   - Response shape mirrors pecker: { decision, reason_code, proof_tx,
//     proof, public_signals } — the same fields the live agent emits, in
//     pecker's order. PROOF_REUSED carries no proof (SPEC §4.2).
import * as proofMod from "./proof.mjs";
import { buildWitness } from "./witness.mjs";
import { snapshotFor } from "./seen.mjs";

export function parseBig(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number");
    return BigInt(Math.trunc(v));
  }
  if (typeof v === "string" && v.trim() !== "") return BigInt(v.trim());
  throw new Error("not a numeric value");
}

function eqStr(a, b) {
  return typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
}

// Pure decision. store is consulted for PROOF_REUSED only.
// Returns { decision, reason_code, checks: [...] }.
export function decide(task, store, cfg) {
  const checks = [];
  const reject = (code, why) => {
    checks.push(why);
    return { decision: "REJECT", reason_code: code, checks };
  };
  const input = task && typeof task === "object" ? task.input : undefined;
  if (!input || typeof input !== "object") {
    return reject(cfg.fallbackRejectReasonCode, "envelope has no input object");
  }
  // 1) VK substitution — string comparison, before any numeric parsing,
  //    so the SPEC §4.1 sample (abbreviated values) resolves here.
  if (typeof input.registered_vk !== "string" || typeof input.proof_vk !== "string") {
    return reject(cfg.fallbackRejectReasonCode, "registered_vk/proof_vk missing or not strings");
  }
  if (!eqStr(input.registered_vk, input.proof_vk)) {
    return reject("VK_SUBSTITUTION", "proof_vk != registered_vk");
  }
  checks.push("vk match");
  // Numeric fields
  let minimum, publicBalance, expiryBlock, currentBlock, amount, maxTransfer;
  try {
    minimum = parseBig(input.minimum);
    publicBalance = parseBig(input.public_balance);
    expiryBlock = parseBig(input.expiry_block);
    currentBlock = parseBig(input.current_block);
    amount = parseBig(input.amount);
    maxTransfer = parseBig(input.max_transfer);
  } catch (e) {
    return reject(cfg.fallbackRejectReasonCode, "numeric field unparsable: " + e.message);
  }
  // 2) Threshold
  if (publicBalance < minimum) return reject("THRESHOLD_MISMATCH", "public_balance < minimum");
  checks.push("threshold ok");
  // 3) Proof reuse
  if (typeof input.proof_tx !== "string" || input.proof_tx === "") {
    return reject(cfg.fallbackRejectReasonCode, "proof_tx missing");
  }
  const reused = cfg.seenRule === "all" ? store.hasAll(input.proof_tx) : store.hasAccepted(input.proof_tx);
  if (reused) return reject("PROOF_REUSED", `proof_tx already seen (rule=${cfg.seenRule})`);
  checks.push("proof_tx fresh");
  // 4) Expiry
  if (currentBlock > expiryBlock) return reject("EXPIRED_CONDITION", "current_block > expiry_block");
  checks.push("not expired");
  // 5) Recipient
  if (typeof input.recipient !== "string" || typeof input.condition_recipient !== "string") {
    return reject(cfg.fallbackRejectReasonCode, "recipient fields missing or not strings");
  }
  if (!eqStr(input.recipient, input.condition_recipient)) {
    return reject("RECIPIENT_MISMATCH", "recipient != condition_recipient");
  }
  checks.push("recipient ok");
  // 6) Amount cap
  if (amount > maxTransfer) return reject("AMOUNT_OVERFLOW", "amount > max_transfer");
  checks.push("amount within cap");
  return { decision: "APPROVE", reason_code: cfg.approveReasonCode, checks };
}

// Full task flow with deadline budgeting (every failure mode has an
// explicit fallback — the DECISION is always returned; the proof is
// attached only when generation + local verification land in budget).
export async function handleGatekeeperTask(task, deps) {
  const { cfg, store, log } = deps;
  const t0 = Date.now();
  const elapsed = () => Date.now() - t0;
  const taskId = task && task.task_id;
  const proofTx = task && task.input ? task.input.proof_tx : undefined;

  // Snapshot the reuse lookups for this task's proof_tx BEFORE deciding
  // (decide() itself stays the live agent's synchronous pure function).
  let storeView = { hasAccepted: () => false, hasAll: () => false };
  if (typeof proofTx === "string" && proofTx !== "") {
    try { storeView = await snapshotFor(store, proofTx); }
    catch (e) { log("warn", `seen-store read failed: ${e.message} — reuse detection degraded for this task`); }
  }
  const d = decide(task, storeView, cfg);

  // Seen-set bookkeeping: every processed reference goes to `all`;
  // APPROVEs additionally go to `accepted` (SPEC §4.3 semantics).
  try {
    if (proofTx) await store.recordAll(proofTx, taskId);
    if (d.decision === "APPROVE" && proofTx) await store.recordAccepted(proofTx, taskId);
  } catch (e) {
    log("error", `seen-store write failed: ${e.message}`);
  }

  const response = { decision: d.decision, reason_code: d.reason_code };
  if (proofTx) response.proof_tx = proofTx;

  // PROOF_REUSED tasks carry no proof (SPEC §4.2) — done.
  if (d.reason_code === "PROOF_REUSED") {
    log("info", `gatekeeper task=${taskId} REJECT/PROOF_REUSED (no proof per spec) ${elapsed()}ms`);
    return response;
  }

  // --- proof pipeline (best effort inside the response budget) ---
  try {
    const witnessCtx = {
      task,
      decisionValue: d.decision === "APPROVE" ? cfg.decisionApproveValue : cfg.decisionRejectValue,
      env: { GATEKEEPER_SALT: cfg.gatekeeperSalt },
    };
    const { input } = buildWitness("gatekeeper", witnessCtx);
    const proveBudget = Math.min(cfg.proofTimeoutMs, Math.max(1000, cfg.gkRespondByMs - elapsed()));
    const { proof, publicSignals, ms } = await proofMod.fullProve("gatekeeper", input, proveBudget);

    let verified = null;
    try { verified = await proofMod.verifyLocal("gatekeeper", publicSignals, proof); }
    catch (e) { log("warn", `gatekeeper local verify errored: ${e.message}`); }
    if (verified === false) {
      log("error", `gatekeeper task=${taskId} proof FAILED local verification — omitting proof`);
    } else {
      response.proof = proof;
      response.public_signals = publicSignals;
      log("info", `gatekeeper task=${taskId} proof generated in ${ms}ms (local verify: ${verified})`);
    }
  } catch (e) {
    // Witness/proof failure (incl. PROOF_TIMEOUT): decision still returned.
    log("error", `gatekeeper task=${taskId} proof pipeline failed (${e.code || e.message}) — responding without proof`);
  }

  log("info", `gatekeeper task=${taskId} -> ${d.decision}/${d.reason_code} in ${elapsed()}ms`);
  return response;
}
