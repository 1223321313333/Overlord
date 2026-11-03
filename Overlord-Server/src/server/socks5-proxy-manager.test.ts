import { describe, expect, test } from "bun:test";
import {
  enqueueSocksBuffer,
  hasSocksConnectionCapacity,
  parseRfc1929Auth,
  verifyProxyAuth,
  SOCKS_PROXY_BIND_HOST,
  SOCKS_PROXY_CONNECT_TIMEOUT_SECONDS,
  SOCKS_PROXY_HANDSHAKE_TIMEOUT_SECONDS,
  SOCKS_PROXY_IDLE_TIMEOUT_SECONDS,
  SOCKS_PROXY_MAX_CLIENT_CONNECTIONS,
  SOCKS_PROXY_MAX_CLIENT_LISTENERS,
  SOCKS_PROXY_MAX_GLOBAL_CONNECTIONS,
  SOCKS_PROXY_MAX_GLOBAL_LISTENERS,
  SOCKS_PROXY_MAX_PENDING_BYTES,
  SOCKS_PROXY_MAX_WRITE_QUEUE_BYTES,
} from "./socks5-proxy-manager";

function buildRfc1929(username: string, password: string): Buffer {
  const uBuf = Buffer.from(username, "utf8");
  const pBuf = Buffer.from(password, "utf8");
  const out = Buffer.alloc(3 + uBuf.length + pBuf.length);
  out[0] = 0x01;
  out[1] = uBuf.length;
  uBuf.copy(out, 2);
  out[2 + uBuf.length] = pBuf.length;
  pBuf.copy(out, 3 + uBuf.length);
  return out;
}

describe("SOCKS proxy security limits", () => {
  test("binds only to loopback by default", () => {
    expect(SOCKS_PROXY_BIND_HOST).toBe("127.0.0.1");
  });

  test("accepts buffers up to a byte limit and rejects overflow without mutating the queue", () => {
    const queue: Buffer[] = [];
    let queuedBytes = enqueueSocksBuffer(queue, 0, Buffer.alloc(4), 6);
    expect(queuedBytes).toBe(4);
    expect(queue).toHaveLength(1);

    queuedBytes = enqueueSocksBuffer(queue, queuedBytes!, Buffer.alloc(3), 6);
    expect(queuedBytes).toBeNull();
    expect(queue).toHaveLength(1);
    expect(queue[0].byteLength).toBe(4);
  });

  test("uses finite pending and slow-writer queue budgets", () => {
    expect(SOCKS_PROXY_MAX_PENDING_BYTES).toBeGreaterThan(0);
    expect(SOCKS_PROXY_MAX_PENDING_BYTES).toBeLessThanOrEqual(64 * 1024 * 1024);
    expect(SOCKS_PROXY_MAX_WRITE_QUEUE_BYTES).toBeGreaterThan(0);
    expect(SOCKS_PROXY_MAX_WRITE_QUEUE_BYTES).toBeLessThanOrEqual(128 * 1024 * 1024);
  });

  test("enforces finite listener and tunnel connection budgets", () => {
    expect(SOCKS_PROXY_MAX_GLOBAL_LISTENERS).toBeGreaterThan(0);
    expect(SOCKS_PROXY_MAX_GLOBAL_LISTENERS).toBeLessThanOrEqual(1_024);
    expect(SOCKS_PROXY_MAX_CLIENT_LISTENERS).toBeGreaterThan(0);
    expect(SOCKS_PROXY_MAX_CLIENT_LISTENERS).toBeLessThanOrEqual(SOCKS_PROXY_MAX_GLOBAL_LISTENERS);

    expect(hasSocksConnectionCapacity(0, 0)).toBe(true);
    expect(hasSocksConnectionCapacity(SOCKS_PROXY_MAX_GLOBAL_CONNECTIONS, 0)).toBe(false);
    expect(hasSocksConnectionCapacity(0, SOCKS_PROXY_MAX_CLIENT_CONNECTIONS)).toBe(false);
  });

  test("uses bounded handshake, connect, and idle timeouts", () => {
    expect(SOCKS_PROXY_HANDSHAKE_TIMEOUT_SECONDS).toBeGreaterThan(0);
    expect(SOCKS_PROXY_HANDSHAKE_TIMEOUT_SECONDS).toBeLessThanOrEqual(30);
    expect(SOCKS_PROXY_CONNECT_TIMEOUT_SECONDS).toBeGreaterThan(0);
    expect(SOCKS_PROXY_CONNECT_TIMEOUT_SECONDS).toBeLessThanOrEqual(60);
    expect(SOCKS_PROXY_IDLE_TIMEOUT_SECONDS).toBeGreaterThan(0);
    expect(SOCKS_PROXY_IDLE_TIMEOUT_SECONDS).toBeLessThanOrEqual(10 * 60);
  });
});

describe("RFC 1929 auth packet parsing", () => {
  test("parses a valid username/password packet", () => {
    const pkt = buildRfc1929("user", "pass");
    const result = parseRfc1929Auth(pkt);
    expect(result).not.toBeNull();
    expect(result!.username).toBe("user");
    expect(result!.password).toBe("pass");
    expect(result!.consumed).toBe(pkt.length);
  });

  test("parses empty username and password", () => {
    const pkt = buildRfc1929("", "");
    const result = parseRfc1929Auth(pkt);
    expect(result).not.toBeNull();
    expect(result!.username).toBe("");
    expect(result!.password).toBe("");
    expect(result!.consumed).toBe(3);
  });

  test("parses a packet with trailing bytes and reports correct consumed count", () => {
    const pkt = Buffer.concat([buildRfc1929("u", "p"), Buffer.from([0x05, 0x01, 0x00])]);
    const result = parseRfc1929Auth(pkt);
    expect(result).not.toBeNull();
    expect(result!.username).toBe("u");
    expect(result!.password).toBe("p");
    expect(pkt.subarray(result!.consumed)).toEqual(Buffer.from([0x05, 0x01, 0x00]));
  });

  test("returns null for a too-short buffer", () => {
    expect(parseRfc1929Auth(Buffer.alloc(0))).toBeNull();
    expect(parseRfc1929Auth(Buffer.from([0x01]))).toBeNull();
  });

  test("returns null when version byte is not 0x01", () => {
    const pkt = buildRfc1929("admin", "secret");
    pkt[0] = 0x05;
    expect(parseRfc1929Auth(pkt)).toBeNull();
  });

  test("returns null when buffer is too short for declared username length", () => {
    const pkt = Buffer.from([0x01, 0x10, 0x61]);
    expect(parseRfc1929Auth(pkt)).toBeNull();
  });

  test("returns null when buffer is too short for declared password length", () => {
    const uBuf = Buffer.from("user", "utf8");
    const partial = Buffer.alloc(2 + uBuf.length + 1 + 5);
    partial[0] = 0x01;
    partial[1] = uBuf.length;
    uBuf.copy(partial, 2);
    partial[2 + uBuf.length] = 0x20; // claims 32-byte password but only 5 bytes follow
    expect(parseRfc1929Auth(partial)).toBeNull();
  });

  test("handles UTF-8 credentials correctly", () => {
    const result = parseRfc1929Auth(buildRfc1929("пользователь", "пароль"));
    expect(result?.username).toBe("пользователь");
    expect(result?.password).toBe("пароль");
  });
});

describe("SOCKS5 timing-safe credential verification", () => {
  test("accepts correct credentials", () => {
    expect(verifyProxyAuth("alice", "s3cr3t", "alice", "s3cr3t")).toBe(true);
  });

  test("rejects wrong username", () => {
    expect(verifyProxyAuth("bob", "s3cr3t", "alice", "s3cr3t")).toBe(false);
  });

  test("rejects wrong password", () => {
    expect(verifyProxyAuth("alice", "wrong", "alice", "s3cr3t")).toBe(false);
  });

  test("rejects both wrong", () => {
    expect(verifyProxyAuth("x", "y", "alice", "s3cr3t")).toBe(false);
  });

  test("rejects username with different length", () => {
    expect(verifyProxyAuth("ali", "s3cr3t", "alice", "s3cr3t")).toBe(false);
  });

  test("rejects password with different length", () => {
    expect(verifyProxyAuth("alice", "s3cr3", "alice", "s3cr3t")).toBe(false);
  });

  test("accepts empty credentials when expected are also empty", () => {
    expect(verifyProxyAuth("", "", "", "")).toBe(true);
  });

  test("rejects non-empty credentials against empty expected", () => {
    expect(verifyProxyAuth("a", "", "", "")).toBe(false);
    expect(verifyProxyAuth("", "b", "", "")).toBe(false);
  });

  test("handles UTF-8 credentials", () => {
    expect(verifyProxyAuth("пользователь", "пароль", "пользователь", "пароль")).toBe(true);
    expect(verifyProxyAuth("пользователь", "неверно", "пользователь", "пароль")).toBe(false);
  });
});
