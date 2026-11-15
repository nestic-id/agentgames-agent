// Tiny structured logger (console-based; Vercel captures stdout).
// Never log secrets — same rule as the live agent.
const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

export function makeLogger(level = "info") {
  const threshold = LEVELS[level] ?? LEVELS.info;
  return (lvl, msg) => {
    if ((LEVELS[lvl] ?? 2) > threshold) return;
    console.log(JSON.stringify({ at: "agentgames-vercel", lvl, msg: String(msg) }));
  };
}
