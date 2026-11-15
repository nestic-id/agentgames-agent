// Groth16 proof generation + local verification via snarkjs.
// Ported from the live agent's src/proof.js with one serverless change:
// the verification keys are PRE-EXPORTED JSON files shipped in artifacts/
// (gatekeeper_vk.json / vfy-policy_vk.json, exported from the same zkeys
// as the live agent's data/*_vk.json) because a serverless filesystem is
// read-only and the snarkjs CLI export step cannot run at cold start.
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";

const ARTIFACTS = fileURLToPath(new URL("../artifacts/", import.meta.url));

const CIRCUITS = {
  gatekeeper: { wasm: "gatekeeper.wasm", zkey: "gatekeeper_final.zkey", vkJson: "gatekeeper_vk.json" },
  "vfy-policy": { wasm: "vfy-policy.wasm", zkey: "vfy-policy_final.zkey", vkJson: "vfy-policy_vk.json" },
};

const vkCache = new Map();

export function circuitPaths(name) {
  const c = CIRCUITS[name];
  if (!c) throw new Error(`unknown circuit: ${name}`);
  return { wasm: ARTIFACTS + c.wasm, zkey: ARTIFACTS + c.zkey, vkJson: ARTIFACTS + c.vkJson };
}

export async function ensureVk(name) {
  if (vkCache.has(name)) return vkCache.get(name);
  const p = circuitPaths(name);
  const vk = JSON.parse(fs.readFileSync(p.vkJson, "utf8"));
  vkCache.set(name, vk);
  return vk;
}

// fullProve with an outer timeout race (snarkjs itself is not cancellable;
// a late proof is simply ignored by the caller when the race is lost).
// Identical to the live agent.
export async function fullProve(name, input, timeoutMs) {
  const p = circuitPaths(name);
  const started = Date.now();
  const prove = groth16.fullProve(input, p.wasm, p.zkey);
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(Object.assign(new Error(`proof generation timed out after ${timeoutMs}ms`), { code: "PROOF_TIMEOUT" })),
      timeoutMs
    );
    if (timer.unref) timer.unref();
  });
  try {
    const { proof, publicSignals } = await Promise.race([prove, timeout]);
    return { proof, publicSignals, ms: Date.now() - started };
  } finally {
    clearTimeout(timer);
  }
}

export async function verifyLocal(name, publicSignals, proof) {
  const vk = await ensureVk(name);
  return groth16.verify(vk, publicSignals, proof);
}

export { CIRCUITS };
