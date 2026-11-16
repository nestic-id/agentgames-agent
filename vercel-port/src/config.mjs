// Central configuration — Vercel port.
// Everything comes from process.env (Vercel project env vars in production;
// the local harness/server sets them for tests). Env var NAMES and defaults
// mirror the live agent's src/config.js exactly for every knob the ported
// logic uses. Kurier and HTTP-server knobs are gone: there is no Kurier in
// the response path and no long-lived server. Secrets are read here only
// and never logged.

function str(name, dflt) {
  const v = process.env[name];
  return v === undefined || v === "" ? dflt : v;
}
function int(name, dflt) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) ? v : dflt;
}
function bool(name, dflt) {
  const v = process.env[name];
  if (v === undefined || v === "") return dflt;
  return /^(1|true|yes|on)$/i.test(v);
}

let cached = null;

export function loadConfig(overrides = {}) {
  if (cached && Object.keys(overrides).length === 0) return cached;
  const cfg = {
    hmacSecret: str("AGENT_GAMES_HMAC_SECRET", ""),
    hmacAlgo: str("HMAC_ALGO", "sha256"), // sha256 | sha512
    hmacEncoding: str("HMAC_ENCODING", "hex"), // hex | base64
    hmacAcceptAlt: bool("HMAC_ACCEPT_ALT", true), // accept the other encoding on verify
    hmacHeader: str("HMAC_HEADER", "x-agent-games-signature"),

    // Gatekeeper (same names/defaults as live)
    approveReasonCode: str("APPROVE_REASON_CODE", "VALID_CONDITION"),
    fallbackRejectReasonCode: str("FALLBACK_REJECT_REASON_CODE", "INVALID_INPUT"),
    seenRule: str("SEEN_RULE", "accepted"), // accepted | all
    decisionApproveValue: str("DECISION_APPROVE_VALUE", "1"),
    decisionRejectValue: str("DECISION_REJECT_VALUE", "0"),
    gatekeeperSalt: str("GATEKEEPER_SALT", "0"),
    gkRespondByMs: int("GK_RESPOND_BY_MS", 50000), // hard platform deadline is 60s

    proofTimeoutMs: int("PROOF_TIMEOUT_MS", 30000),

    // Steal the VFY (same names/defaults as live)
    stealRespondByMs: int("STEAL_RESPOND_BY_MS", 25000), // platform window ~30s
    stealProofRequired: bool("STEAL_PROOF_REQUIRED", false),
    strategySalt: str("STRATEGY_SALT", ""),
    // Live format: a JSON array string, e.g. "[10,70,0,0,0,0,0,0]".
    strategyParamsJson: str("STRATEGY_PARAMS", ""),

    // Seen-store backend: auto | blob | memory | file
    //   auto  -> blob when BLOB_READ_WRITE_TOKEN is set, else memory
    //   file  -> local JSON file at SEEN_FILE_PATH (local dev/parity only)
    seenBackend: str("SEEN_BACKEND", "auto"),
    seenFilePath: str("SEEN_FILE_PATH", ""),

    // Task-payload archive backend: auto | blob | memory | off
    //   auto  -> blob when BLOB_READ_WRITE_TOKEN is set, else off
    // Archiving is fail-open and raced against archiveTimeoutMs.
    archiveBackend: str("ARCHIVE_BACKEND", "auto"),
    archiveTimeoutMs: int("ARCHIVE_TIMEOUT_MS", 2000),

    logLevel: str("LOG_LEVEL", "info"),
  };
  Object.assign(cfg, overrides);
  if (Object.keys(overrides).length === 0) cached = cfg;
  return cfg;
}

export function validateConfig(cfg) {
  const errors = [];
  if (!cfg.hmacSecret) errors.push("AGENT_GAMES_HMAC_SECRET is not set");
  if (!["sha256", "sha512"].includes(cfg.hmacAlgo)) errors.push(`HMAC_ALGO must be sha256|sha512 (got ${cfg.hmacAlgo})`);
  if (!["hex", "base64"].includes(cfg.hmacEncoding)) errors.push(`HMAC_ENCODING must be hex|base64 (got ${cfg.hmacEncoding})`);
  if (!["accepted", "all"].includes(cfg.seenRule)) errors.push(`SEEN_RULE must be accepted|all (got ${cfg.seenRule})`);
  return errors;
}
