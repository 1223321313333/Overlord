import { logger } from "../logger";
import { timingSafeEqual } from "crypto";
import { validateAgentReplayHeaders } from "./agent-nonce-store";
import { verifyAgentClientCert } from "./mtls-agent-auth";

let warnedDisableAuthIgnored = false;
let loggedAuthDisabledByEnv = false;
let loggedAuthDisabledNoToken = false;

// Whether replay-protection headers are enforced (opt-out for legacy agents).
const REPLAY_PROTECTION_ENABLED =
  String(process.env.OVERLORD_AGENT_REPLAY_PROTECTION ?? "true").toLowerCase() !== "false";

function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export function isAuthorizedAgentRequest(
  req: Request,
  agentToken?: string,
): boolean {
  const disableAuth =
    String(process.env.OVERLORD_DISABLE_AGENT_AUTH || "").toLowerCase() ===
    "true";
  if (disableAuth) {
    const nodeEnv = String(process.env.NODE_ENV || "development").toLowerCase();
    if (nodeEnv === "production") {
      if (!warnedDisableAuthIgnored) {
        warnedDisableAuthIgnored = true;
        logger.warn("[auth] OVERLORD_DISABLE_AGENT_AUTH is ignored in production mode");
      }
    } else {
      if (!loggedAuthDisabledByEnv) {
        loggedAuthDisabledByEnv = true;
        logger.info("[auth] Agent auth explicitly disabled by OVERLORD_DISABLE_AGENT_AUTH=true (non-production mode)");
      }
      return true;
    }
  }

  const token = agentToken?.trim();
  if (!token) {
    if (!loggedAuthDisabledNoToken) {
      loggedAuthDisabledNoToken = true;
      logger.error("[auth] Agent auth token is missing; agent requests will be rejected");
    }
    return false;
  }

  const headerToken = req.headers.get("x-agent-token");
  if (headerToken === null || !safeCompare(headerToken, token)) {
    return false;
  }

  // Replay protection: validate timestamp + nonce (can be disabled for legacy agents).
  if (REPLAY_PROTECTION_ENABLED) {
    const replayError = validateAgentReplayHeaders(req);
    if (replayError) {
      logger.warn(`[auth] Agent replay check failed: ${replayError}`);
      return false;
    }
  }

  // mTLS: verify client certificate when OVERLORD_MTLS_AGENT_CA is configured.
  const mtlsError = verifyAgentClientCert(req);
  if (mtlsError) {
    logger.warn(`[auth] ${mtlsError}`);
    return false;
  }

  return true;
}
