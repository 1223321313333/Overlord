/**
 * Replay-attack protection for agent connections.
 *
 * Each agent request must include two headers:
 *   X-Agent-TS    — Unix timestamp in milliseconds (string)
 *   X-Agent-Nonce — 16-byte cryptographically-random hex string
 *
 * The server:
 *  1. Rejects requests whose timestamp deviates by more than CLOCK_SKEW_MS.
 *  2. Rejects requests whose nonce has already been seen within the TTL window.
 *
 * Nonces are stored in a fixed-capacity LRU-style map and expire after TTL_MS.
 */

const CLOCK_SKEW_MS = 30_000;   // ±30 seconds
const NONCE_TTL_MS  = 120_000;  // keep nonces for 2 minutes
const MAX_NONCES    = 100_000;  // hard cap to prevent memory exhaustion

type NonceEntry = { seenAt: number };

const nonceStore = new Map<string, NonceEntry>();

// Prune expired entries every minute.
setInterval(() => {
  const cutoff = Date.now() - NONCE_TTL_MS;
  for (const [nonce, entry] of nonceStore) {
    if (entry.seenAt < cutoff) nonceStore.delete(nonce);
  }
}, 60_000);

/**
 * Validates X-Agent-TS and X-Agent-Nonce headers.
 * Returns null on success, or an error string on failure.
 */
export function validateAgentReplayHeaders(req: Request): string | null {
  const tsHeader = req.headers.get("x-agent-ts");
  const nonce    = req.headers.get("x-agent-nonce");

  if (!tsHeader || !nonce) {
    return "missing replay-protection headers (x-agent-ts / x-agent-nonce)";
  }

  // Validate timestamp
  const ts = Number(tsHeader);
  if (!Number.isFinite(ts) || ts <= 0) {
    return "invalid x-agent-ts";
  }
  const delta = Math.abs(Date.now() - ts);
  if (delta > CLOCK_SKEW_MS) {
    return `clock skew too large (${delta}ms, max ${CLOCK_SKEW_MS}ms)`;
  }

  // Validate nonce format: 32 hex chars (16 bytes)
  if (!/^[0-9a-f]{32}$/i.test(nonce)) {
    return "invalid x-agent-nonce format";
  }

  // Check for replay
  if (nonceStore.has(nonce)) {
    return "replayed nonce";
  }

  // Enforce cap
  if (nonceStore.size >= MAX_NONCES) {
    // Evict oldest entry
    const oldest = nonceStore.keys().next().value;
    if (oldest) nonceStore.delete(oldest);
  }

  nonceStore.set(nonce, { seenAt: Date.now() });
  return null;
}
