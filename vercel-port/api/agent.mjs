// Vercel serverless entry — mirrors pecker's api/agent.mjs shape.
// The registered platform endpoint path is /agent (vercel.json rewrites
// /agent -> /api/agent). One function serves both tracks; routing is by
// envelope content, exactly like the live agent's POST /agent route.
//
// GET serves two things:
//   - plain GET            -> health (unchanged)
//   - GET ?archive=<path>  -> read back one archived task record from
//     the (private) Blob archive. Requires a valid x-agent-games-signature
//     header: HMAC (same scheme as POST) over the pathname string itself.
//     No valid signature -> 401.
import { handle, getDeps } from "../src/handler.mjs";
import * as hmac from "../src/hmac.mjs";

export async function POST(request) {
  const raw = Buffer.from(await request.arrayBuffer());
  const deps = getDeps();
  const r = await handle(raw, request.headers.get(deps.cfg.hmacHeader), deps);
  return new Response(r.body, { status: r.status, headers: r.headers });
}

export function HEAD() {
  return new Response(null, { status: 200 });
}

export async function GET(request) {
  const deps = getDeps();
  let rel = null;
  try {
    if (request && request.url) rel = new URL(request.url).searchParams.get("archive");
  } catch (e) { /* unparseable URL -> plain health */ }

  if (!rel) {
    return Response.json({
      ok: true,
      protocolVersion: "v1",
      service: "agentgames-agent-vercel",
      configured: Boolean(deps.cfg.hmacSecret),
      seenBackend: deps.store.backend,
      archiveBackend: deps.archive ? deps.archive.backend : "off",
    });
  }

  // Archive read-back: the pathname must be a relative archive/ path,
  // and the caller must sign the pathname string with the agent secret.
  if (rel.includes("..") || rel.startsWith("/") || !rel.startsWith("archive/")) {
    return Response.json({ error: "bad_archive_path" }, { status: 400 });
  }
  const verdict = hmac.verify(deps.cfg, request.headers.get(deps.cfg.hmacHeader), Buffer.from(rel, "utf8"));
  if (!verdict.ok) {
    return Response.json({ error: "invalid_signature" }, { status: 401 });
  }
  if (!deps.archive || deps.archive.backend === "off") {
    return Response.json({ error: "archive_unavailable" }, { status: 404 });
  }
  const record = await deps.archive.get(rel);
  if (!record) {
    return Response.json({ error: "not_found" }, { status: 404 });
  }
  return Response.json(record);
}
