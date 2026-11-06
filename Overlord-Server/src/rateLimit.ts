import Database from "bun:sqlite";
import { resolve } from "path";
import { logger } from "./logger";
import { getConfig } from "./config";
import { ensureDataDir } from "./paths";

interface RateLimitEntry {
  attempts: number;
  firstAttempt: number;
  lockedUntil?: number;
}

type RequestRateLimitPolicy = {
  maxRequests: number;
  windowMs: number;
  lockoutMs: number;
};

const dataDir = ensureDataDir();
const rlDb = new Database(resolve(dataDir, "overlord.db"));

rlDb.run(`
  CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL,
    first_attempt INTEGER NOT NULL,
    locked_until INTEGER
  );
`);

function rlGet(key: string): RateLimitEntry | undefined {
  const row = rlDb.query<{ attempts: number; first_attempt: number; locked_until: number | null }, [string]>(
    "SELECT attempts, first_attempt, locked_until FROM rate_limits WHERE key = ?",
  ).get(key);
  if (!row) return undefined;
  return {
    attempts: row.attempts,
    firstAttempt: row.first_attempt,
    lockedUntil: row.locked_until ?? undefined,
  };
}

function rlSet(key: string, entry: RateLimitEntry): void {
  rlDb.run(
    "INSERT OR REPLACE INTO rate_limits (key, attempts, first_attempt, locked_until) VALUES (?, ?, ?, ?)",
    [key, entry.attempts, entry.firstAttempt, entry.lockedUntil ?? null],
  );
}

function rlDelete(key: string): void {
  rlDb.run("DELETE FROM rate_limits WHERE key = ?", [key]);
}

const requestRateLimitStore = new Map<string, RateLimitEntry>();

const CLEANUP_INTERVAL = 60 * 1000;

function numberFromEnv(name: string, fallback: number): number {
  const parsed = Number(process.env[name]);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function getRateLimitPolicy() {
  const security = getConfig().security;
  const maxAttempts = Math.min(50, Math.max(1, Number(security.loginMaxAttempts) || 5));
  const windowMs = Math.min(24 * 60 * 60 * 1000, Math.max(60 * 1000, (Number(security.loginWindowMinutes) || 15) * 60 * 1000));
  const lockoutMs = Math.min(24 * 60 * 60 * 1000, Math.max(60 * 1000, (Number(security.loginLockoutMinutes) || 30) * 60 * 1000));
  return { maxAttempts, windowMs, lockoutMs };
}

export function isRateLimited(ip: string): {
  limited: boolean;
  retryAfter?: number;
} {
  const policy = getRateLimitPolicy();
  const entry = rlGet(ip);

  if (!entry) {
    return { limited: false };
  }

  const now = Date.now();

  if (entry.lockedUntil && entry.lockedUntil > now) {
    const retryAfter = Math.ceil((entry.lockedUntil - now) / 1000);
    return { limited: true, retryAfter };
  }

  if (now - entry.firstAttempt > policy.windowMs) {
    rlDelete(ip);
    return { limited: false };
  }

  if (entry.attempts >= policy.maxAttempts) {
    const lockedUntil = now + policy.lockoutMs;
    rlSet(ip, { ...entry, lockedUntil });
    const retryAfter = Math.ceil(policy.lockoutMs / 1000);
    logger.warn(
      `[rate-limit] IP ${ip} locked out for ${retryAfter}s after ${entry.attempts} failed attempts`,
    );
    return { limited: true, retryAfter };
  }

  return { limited: false };
}

export function recordFailedAttempt(ip: string): void {
  const policy = getRateLimitPolicy();
  const now = Date.now();
  const entry = rlGet(ip);

  if (!entry) {
    rlSet(ip, { attempts: 1, firstAttempt: now });
    return;
  }

  if (now - entry.firstAttempt > policy.windowMs) {
    rlSet(ip, { attempts: 1, firstAttempt: now });
    return;
  }

  const updated = { ...entry, attempts: entry.attempts + 1 };
  rlSet(ip, updated);
  logger.debug(
    `[rate-limit] IP ${ip} failed attempt ${updated.attempts}/${policy.maxAttempts}`,
  );
}

export function recordSuccessfulAttempt(ip: string): void {
  rlDelete(ip);
}

function makeRequestPolicy(prefix: string, defaults: RequestRateLimitPolicy): RequestRateLimitPolicy {
  return {
    maxRequests: Math.min(
      1000,
      Math.max(1, numberFromEnv(`OVERLORD_${prefix}_RATE_LIMIT_MAX`, defaults.maxRequests)),
    ),
    windowMs: Math.min(
      60 * 60 * 1000,
      Math.max(10 * 1000, numberFromEnv(`OVERLORD_${prefix}_RATE_LIMIT_WINDOW_SECONDS`, defaults.windowMs / 1000) * 1000),
    ),
    lockoutMs: Math.min(
      60 * 60 * 1000,
      Math.max(10 * 1000, numberFromEnv(`OVERLORD_${prefix}_RATE_LIMIT_LOCKOUT_SECONDS`, defaults.lockoutMs / 1000) * 1000),
    ),
  };
}

function consumeRequestRateLimit(
  key: string,
  label: string,
  policy: RequestRateLimitPolicy,
): { limited: boolean; retryAfter?: number } {
  const now = Date.now();
  const entry = requestRateLimitStore.get(key);

  if (entry?.lockedUntil && entry.lockedUntil > now) {
    return { limited: true, retryAfter: Math.ceil((entry.lockedUntil - now) / 1000) };
  }

  if (!entry || now - entry.firstAttempt > policy.windowMs) {
    requestRateLimitStore.set(key, { attempts: 1, firstAttempt: now });
    return { limited: false };
  }

  entry.attempts++;
  if (entry.attempts > policy.maxRequests) {
    entry.lockedUntil = now + policy.lockoutMs;
    const retryAfter = Math.ceil(policy.lockoutMs / 1000);
    logger.warn(
      `[rate-limit] ${label} rate limit exceeded for ${key}; locked for ${retryAfter}s after ${entry.attempts} requests`,
    );
    return { limited: true, retryAfter };
  }

  return { limited: false };
}

export function consumeLoginPageRateLimit(ip: string): { limited: boolean; retryAfter?: number } {
  const policy = makeRequestPolicy("LOGIN_PAGE", {
    maxRequests: 60,
    windowMs: 5 * 60 * 1000,
    lockoutMs: 10 * 60 * 1000,
  });
  return consumeRequestRateLimit(`login-page:${ip}`, "Login page", policy);
}

export function consumeUnauthorizedRateLimit(ip: string): { limited: boolean; retryAfter?: number } {
  const policy = makeRequestPolicy("UNAUTHORIZED", {
    maxRequests: 120,
    windowMs: 5 * 60 * 1000,
    lockoutMs: 10 * 60 * 1000,
  });
  return consumeRequestRateLimit(`unauthorized:${ip}`, "Unauthorized request", policy);
}

export function consumeSolRpcRateLimit(
  userId: number,
  action: "balance" | "publish",
): { limited: boolean; retryAfter?: number } {
  const policy = action === "publish"
    ? makeRequestPolicy("SOL_PUBLISH", { maxRequests: 3, windowMs: 5 * 60 * 1000, lockoutMs: 5 * 60 * 1000 })
    : makeRequestPolicy("SOL_BALANCE", { maxRequests: 12, windowMs: 60 * 1000, lockoutMs: 60 * 1000 });
  return consumeRequestRateLimit(`sol-${action}:${userId}`, `Solana ${action}`, policy);
}

export function consumePushSubscriptionMutationRateLimit(
  userId: number,
): { limited: boolean; retryAfter?: number } {
  const policy = makeRequestPolicy("PUSH_SUBSCRIPTION", {
    maxRequests: 20,
    windowMs: 60 * 1000,
    lockoutMs: 60 * 1000,
  });
  return consumeRequestRateLimit(
    `push-subscription:${userId}`,
    "Push subscription mutation",
    policy,
  );
}

export function clearRequestRateLimitsForTests(): void {
  requestRateLimitStore.clear();
}

function cleanupExpired(): void {
  const policy = getRateLimitPolicy();
  const now = Date.now();
  let cleaned = 0;

  const windowThreshold = now - policy.windowMs;
  const result = rlDb.run(
    "DELETE FROM rate_limits WHERE (locked_until IS NULL AND first_attempt < ?) OR (locked_until IS NOT NULL AND locked_until < ?)",
    [windowThreshold, now],
  );
  cleaned += result.changes;

  for (const [key, entry] of requestRateLimitStore.entries()) {
    const expired = now - entry.firstAttempt > 60 * 60 * 1000;
    const lockoutExpired = entry.lockedUntil && entry.lockedUntil < now;
    if (expired || lockoutExpired) {
      requestRateLimitStore.delete(key);
      cleaned++;
    }
  }

  if (cleaned > 0) {
    logger.debug(`[rate-limit] Cleaned up ${cleaned} expired entries`);
  }
}

export function getRateLimitStats(): { total: number; locked: number } {
  const now = Date.now();
  const total = (rlDb.query<{ c: number }, []>("SELECT COUNT(*) AS c FROM rate_limits").get()?.c) ?? 0;
  const locked = (rlDb.query<{ c: number }, [number]>("SELECT COUNT(*) AS c FROM rate_limits WHERE locked_until > ?").get(now)?.c) ?? 0;
  return { total, locked };
}

setInterval(cleanupExpired, CLEANUP_INTERVAL);

const initialPolicy = getRateLimitPolicy();
logger.info(
  `[rate-limit] Initialized: ${initialPolicy.maxAttempts} attempts per ${Math.round(initialPolicy.windowMs / 60000)} minutes, ${Math.round(initialPolicy.lockoutMs / 60000)} minute lockout`,
);
