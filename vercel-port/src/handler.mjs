// Transport core shared by the Vercel function (api/agent.mjs) and the
// local dev server (src/server.mjs). Ported from the live agent's
// src/server.js handlePost semantics:
//   - HMAC verified over the RAW body BEFORE JSON parsing (401 on mismatch)
//   - preflight honoured on every POST
//   - type-sniffed routing (single endpoint serves both tracks, like
//     pecker's single Vercel function)
//   - EVERY JSON response is signed over its raw body
//   - fail closed: gatekeeper handler crash -> REJECT, steal -> HOLD
import { loadConfig } from "./config.mjs";
import * as hmac from "./hmac.mjs";
import { makeLogger } from "./log.mjs";
import { createSeenStore } from "./seen.mjs";
import { handleGatekeeperTask } from "./gatekeeper.mjs";
import { handleStealTurn } from "./steal.mjs";

let depsCache = null;
export function getDeps(overrides = {}) {
  if (depsCache && Object.keys(overrides).length === 0) return depsCache;
  const cfg = loadConfig(overrides.cfg || {});
  const log = makeLogger(cfg.logLevel);
  const store = createSeenStore(cfg, log);
  const deps = { cfg, store, log };
  if (Object.keys(overrides).length === 0) depsCache = deps;
  return deps;
}

// handle(rawBody: Buffer, signatureHeader: string|undefined, deps)
//   -> { status, headers, body } where body is the exact raw string sent.
export async function handle(raw, signatureHeader, deps) {
  const { cfg, log } = deps;

  function sendJson(status, obj) {
    const body = JSON.stringify(obj);
    const headers = { "content-type": "application/json", "cache-control": "no-store" };
    if (cfg.hmacSecret) headers[cfg.hmacHeader] = hmac.sign(cfg, Buffer.from(body, "utf8"));
    return { status, headers, body };
  }

  // HMAC BEFORE parse — reject on mismatch.
  const verdict = hmac.verify(cfg, signatureHeader, raw);
  if (!verdict.ok) {
    log("warn", "rejected unsigned/badly-signed POST");
    return sendJson(401, { error: "invalid_signature" });
  }
  if (verdict.encoding !== cfg.hmacEncoding) {
    log("info", `inbound signature matched ALT encoding=${verdict.encoding} (configured ${cfg.hmacEncoding})`);
  }

  let body;
  try {
    body = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    return sendJson(400, { error: "invalid_json" });
  }

  // Preflight is honoured on every POST route.
  if (body && body.type === "agent-games.preflight.v1") {
    log("info", `preflight ok (agent_id=${body.agent_id || "?"})`);
    return sendJson(200, { ok: true, protocolVersion: "v1" });
  }

  const isSteal = body && (body.eventId === "steal-the-vfy" || body.matchId !== undefined);
  const isGatekeeper = body && typeof body.type === "string" && body.type.includes("proof-gatekeeper");
  try {
    if (isSteal) return sendJson(200, await handleStealTurn(body, deps));
    if (isGatekeeper) return sendJson(200, await handleGatekeeperTask(body, deps));
    // Unknown payload shape: fail closed to the gatekeeper default,
    // exactly like the live agent's /agent route.
    return sendJson(200, await handleGatekeeperTask(body, deps));
  } catch (e) {
    // Handlers are designed not to throw; last-resort fail-closed.
    log("error", `handler crashed: ${e.stack || e.message}`);
    if (isSteal) {
      return sendJson(200, await handleStealTurn(null, deps).catch(() => ({ action: { type: "HOLD" } })));
    }
    return sendJson(200, { decision: "REJECT", reason_code: cfg.fallbackRejectReasonCode });
  }
}
