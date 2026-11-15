// Local dev/test server — wraps the SAME transport core the Vercel
// function uses (mirrors pecker's src/server.mjs). Local only:
//   node src/server.mjs            (PORT env, default 3107, 127.0.0.1)
// Loads vercel-port/.env if present (this project's own file — never the
// live agent's .env). Routes mirror the live agent:
//   POST /agent | /agent/gatekeeper | /agent/steal, GET /health.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { handle, getDeps } from "./handler.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
try {
  const text = fs.readFileSync(path.join(HERE, "..", ".env"), "utf8");
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && !line.trim().startsWith("#") && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
} catch (e) { /* no local .env — env comes from the shell/harness */ }

const MAX_BODY_BYTES = 1024 * 1024;

export function createAgentServer(deps = getDeps()) {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (req.method === "GET" && url.pathname === "/health") {
      const body = JSON.stringify({ ok: true, service: "agentgames-agent-vercel", seenBackend: deps.store.backend, time: new Date().toISOString() });
      res.writeHead(200, { "content-type": "application/json" }).end(body);
      return;
    }
    if (req.method !== "POST" || !["/agent", "/api/agent", "/agent/gatekeeper", "/agent/steal"].includes(url.pathname)) {
      res.writeHead(404, { "content-type": "application/json" }).end('{"error":"not_found"}');
      return;
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) { res.writeHead(413).end(); return; }
      chunks.push(chunk);
    }
    const r = await handle(Buffer.concat(chunks), req.headers[deps.cfg.hmacHeader], deps);
    res.writeHead(r.status, r.headers).end(r.body);
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3107);
  createAgentServer().listen(port, "127.0.0.1", () => console.log(`agent (vercel-port, local) listening on 127.0.0.1:${port}`));
}
