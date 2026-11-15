// HMAC signing/verification for x-agent-games-signature.
// Ported verbatim (semantics) from the live agent's src/hmac.js:
// HMAC over the RAW body, configured digest/encoding, verification
// optionally accepts the alternate encoding and reports which matched.
import crypto from "node:crypto";

function digestStr(cfg, bodyBuffer, encoding) {
  return crypto.createHmac(cfg.hmacAlgo, cfg.hmacSecret).update(bodyBuffer).digest(encoding);
}

export function sign(cfg, bodyBuffer) {
  return digestStr(cfg, bodyBuffer, cfg.hmacEncoding);
}

function safeEqualStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Returns { ok, encoding } — encoding is the one that matched (or null).
export function verify(cfg, headerValue, bodyBuffer) {
  if (!headerValue || typeof headerValue !== "string") return { ok: false, encoding: null };
  if (!cfg.hmacSecret) return { ok: false, encoding: null };
  if (safeEqualStr(headerValue, digestStr(cfg, bodyBuffer, cfg.hmacEncoding))) {
    return { ok: true, encoding: cfg.hmacEncoding };
  }
  if (cfg.hmacAcceptAlt) {
    const alt = cfg.hmacEncoding === "hex" ? "base64" : "hex";
    if (safeEqualStr(headerValue, digestStr(cfg, bodyBuffer, alt))) return { ok: true, encoding: alt };
  }
  return { ok: false, encoding: null };
}
