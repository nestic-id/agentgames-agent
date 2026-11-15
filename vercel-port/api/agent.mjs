// Vercel serverless entry — mirrors pecker's api/agent.mjs shape.
// The registered platform endpoint path is /agent (vercel.json rewrites
// /agent -> /api/agent). One function serves both tracks; routing is by
// envelope content, exactly like the live agent's POST /agent route.
import { handle, getDeps } from "../src/handler.mjs";

export async function POST(request) {
  const raw = Buffer.from(await request.arrayBuffer());
  const deps = getDeps();
  const r = await handle(raw, request.headers.get(deps.cfg.hmacHeader), deps);
  return new Response(r.body, { status: r.status, headers: r.headers });
}

export function HEAD() {
  return new Response(null, { status: 200 });
}

export function GET() {
  const deps = getDeps();
  return Response.json({
    ok: true,
    protocolVersion: "v1",
    service: "agentgames-agent-vercel",
    configured: Boolean(deps.cfg.hmacSecret),
    seenBackend: deps.store.backend,
  });
}
