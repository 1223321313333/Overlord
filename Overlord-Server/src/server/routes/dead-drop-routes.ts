/**
 * Dead-drop resolver endpoint.
 *
 * GET /api/dd
 *
 * Returns the server's own WebSocket URL list as a plain-text newline-
 * separated list, HMAC-signed so agents can verify authenticity.
 *
 * The response is intentionally generic-looking (plain text, no CORS, no
 * auth headers beyond the token-derived HMAC signature) so it blends in
 * with background HTTP traffic.
 *
 * Agents using the dead-drop flow:
 *   1. Query a public location (DNS TXT, GitHub Gist, etc.) to learn
 *      the URL of this endpoint.
 *   2. Fetch GET /api/dd to get the current server list.
 *   3. Verify the HMAC signature using the shared agent token.
 *   4. Connect via WebSocket as normal.
 *
 * Signing: HMAC-SHA256(key=agentToken, message=sortedURLs\ntimestamp)
 * where timestamp is the Unix second truncated to the nearest 60 seconds
 * (1-minute validity window, rolling).
 */

import { createHmac } from "crypto";
import { getConfig } from "../../config";
import { logger } from "../../logger";

function buildServerUrlList(): string[] {
  const cfg = getConfig();
  const port = cfg.server.port;
  const host = cfg.server.host === "0.0.0.0" || cfg.server.host === "::"
    ? String(process.env.OVERLORD_PUBLIC_HOST ?? "").trim() || "localhost"
    : cfg.server.host;
  const scheme = process.env.OVERLORD_TLS_OFFLOAD?.toLowerCase() === "true" ? "wss" : "wss";
  return [`${scheme}://${host}:${port}`];
}

function signServerList(urls: string[], agentToken: string): string {
  // Rolling 60-second window so stale responses are rejected by agents.
  const window = Math.floor(Date.now() / 1000 / 60);
  const message = [...urls].sort().join("\n") + "\n" + window;
  return createHmac("sha256", agentToken).update(message).digest("base64url");
}

export function handleDeadDropRoutes(
  req: Request,
  url: URL,
): Response | null {
  if (req.method !== "GET" || url.pathname !== "/api/dd") return null;

  const cfg = getConfig();
  const token = cfg.auth.agentToken?.trim();
  if (!token) {
    // Dead-drop requires an agent token to be meaningful.
    return new Response("", { status: 204 });
  }

  const urls = buildServerUrlList();
  const sig = signServerList(urls, token);
  const body = urls.join("\n");

  logger.debug(`[dead-drop] Served ${urls.length} URL(s)`);

  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "X-DD-Sig": sig,
      // No Cache-Control — let proxies cache freely to reduce fingerprinting.
    },
  });
}
