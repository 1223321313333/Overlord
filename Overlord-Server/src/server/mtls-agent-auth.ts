/**
 * mTLS client certificate verification for agent connections.
 *
 * When OVERLORD_MTLS_AGENT_CA is set to a PEM file path, all agent WebSocket
 * upgrade requests must present a client certificate signed by that CA.
 * The certificate's fingerprint (SHA-256 of SubjectPublicKeyInfo) is logged
 * for audit purposes.
 *
 * Bun exposes the verified peer certificate chain on the TLS connection state;
 * we access it via the undocumented `tls` field on the Request object that
 * Bun populates when `requestCert: true` is set in the server TLS options.
 *
 * To enable:
 *   1. Set OVERLORD_MTLS_AGENT_CA=/path/to/agent-ca.pem
 *   2. Add requestCert: true to Bun.serve tls options (see main-server.ts)
 *   3. Distribute client cert+key to agents (TLSClientCert / TLSClientKey config)
 *
 * Fallback: when the env var is not set, mTLS verification is skipped and the
 * existing token-based auth is the only gate.
 */

import { readFileSync } from "fs";
import { X509Certificate, createHash } from "crypto";
import { logger } from "../logger";

type AgentMtlsConfig = {
  required: boolean;
  caCert: X509Certificate | null;
  caFingerprint: string;
};

let _config: AgentMtlsConfig | null = null;

function loadMtlsConfig(): AgentMtlsConfig {
  if (_config) return _config;

  const caPath = String(process.env.OVERLORD_MTLS_AGENT_CA ?? "").trim();
  if (!caPath) {
    _config = { required: false, caCert: null, caFingerprint: "" };
    return _config;
  }

  try {
    const pem = readFileSync(caPath, "utf8");
    const cert = new X509Certificate(pem);
    const fp = createHash("sha256")
      .update(cert.raw)
      .digest("hex")
      .replace(/(.{2})/g, "$1:")
      .slice(0, -1);
    logger.info(`[mTLS] Agent client-cert CA loaded: ${cert.subject} (${fp})`);
    _config = { required: true, caCert: cert, caFingerprint: fp };
  } catch (err) {
    logger.error(`[mTLS] Failed to load agent CA from ${caPath}: ${(err as Error).message}`);
    _config = { required: false, caCert: null, caFingerprint: "" };
  }
  return _config;
}

/**
 * Extracts the peer certificate from a Bun Request's TLS state.
 * Bun adds a non-standard `tls` property to requests when requestCert is set.
 */
function getPeerCert(req: Request): X509Certificate | null {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tls = (req as any).tls as { peerCertificate?: { rawData?: ArrayBuffer } } | undefined;
  if (!tls?.peerCertificate?.rawData) return null;
  try {
    return new X509Certificate(Buffer.from(tls.peerCertificate.rawData));
  } catch {
    return null;
  }
}

/**
 * Returns null if the request passes mTLS verification (or mTLS is not configured).
 * Returns an error string if verification fails.
 */
export function verifyAgentClientCert(req: Request): string | null {
  const cfg = loadMtlsConfig();
  if (!cfg.required || !cfg.caCert) return null;

  const peerCert = getPeerCert(req);
  if (!peerCert) {
    return "mTLS: no client certificate presented";
  }

  // Verify the cert was signed by our agent CA.
  try {
    if (!peerCert.verify(cfg.caCert.publicKey)) {
      return "mTLS: client certificate not signed by agent CA";
    }
  } catch {
    return "mTLS: client certificate verification error";
  }

  // Check validity window.
  const now = new Date();
  if (now < new Date(peerCert.validFrom) || now > new Date(peerCert.validTo)) {
    return `mTLS: client certificate expired or not yet valid (${peerCert.validFrom} – ${peerCert.validTo})`;
  }

  const fp = createHash("sha256").update(peerCert.raw).digest("base64");
  logger.debug(`[mTLS] Agent client cert accepted: ${peerCert.subject} sha256/${fp}`);
  return null;
}
