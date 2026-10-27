/**
 * Stateless gateway tokens for single-credential MCP clients.
 *
 * Logger: createLogger("gateway-token"). Records are structured JSON on
 * stderr; raise verbosity by filtering the service logs for that service
 * name (the repository logger emits debug records through the same sink).
 * Main failure modes: GATEWAY_TOKEN_SECRET missing (feature disabled),
 * malformed or tampered token bytes, GCM authentication failure, expired
 * token, and a payload whose shape or version is not exactly v1. Every
 * defect fails closed by returning undefined.
 *
 * A gateway token is issued only after a one-time enrollment has verified
 * BOTH the caller's Dokploy account login and the caller's Dokploy API
 * key. The token then becomes the single credential a connector stores:
 * the Dokploy API key travels inside the token, encrypted with
 * AES-256-GCM, so the gateway can recover it per request while the client
 * never sends a password again. The password is never part of a token.
 *
 * Token format: "gt1." + base64url(iv || ciphertext || tag), with a
 * 12-byte IV and a 16-byte GCM tag. Plaintext is JSON:
 * { v: 1, email, apiKey, iat, exp, jti } with iat/exp in epoch seconds.
 * Nothing is stored server-side: possession of a valid token is the
 * enrollment proof until exp. Rotating GATEWAY_TOKEN_SECRET therefore
 * revokes every issued token at once.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { createLogger } from "./logger.js";

const logger = createLogger("gateway-token");

export const GATEWAY_TOKEN_PREFIX = "gt1.";

const TOKEN_VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_TOKEN_LENGTH = 8192;
const MAX_EMAIL_LENGTH = 254;
const MAX_API_KEY_LENGTH = 512;
const DEFAULT_TTL_DAYS = 30;
const MIN_TTL_DAYS = 1;
const MAX_TTL_DAYS = 365;
const SECONDS_PER_DAY = 86_400;

export interface GatewayTokenIssueInput {
  email: string;
  apiKey: string;
  /** Milliseconds since the epoch. Defaults to Date.now(). */
  now?: number;
}

export interface GatewayTokenClaims {
  email: string;
  apiKey: string;
  /** Expiry, epoch seconds. */
  exp: number;
  jti: string;
}

interface GatewayTokenPayload {
  v: number;
  email: string;
  apiKey: string;
  iat: number;
  exp: number;
  jti: string;
}

/** Whether the gateway-token feature is configured (secret present). */
export function isGatewayTokenConfigured(): boolean {
  const secret = process.env.GATEWAY_TOKEN_SECRET;
  return typeof secret === "string" && secret.length > 0;
}

/**
 * Resolve the AES-256 key from GATEWAY_TOKEN_SECRET. A secret that
 * base64-decodes to exactly 32 bytes is used as the raw key; anything
 * else is hashed with SHA-256 so any non-empty string works as a secret.
 * Returns undefined when the secret is missing or empty.
 */
function deriveGatewayTokenKey(): Buffer | undefined {
  const secret = process.env.GATEWAY_TOKEN_SECRET;
  if (!secret) {
    return undefined;
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(secret) && secret.length % 4 !== 1) {
    const decoded = Buffer.from(secret, "base64");
    if (decoded.length === 32) {
      return decoded;
    }
  }
  return createHash("sha256").update(secret, "utf8").digest();
}

/** Token lifetime in days: GATEWAY_TOKEN_TTL_DAYS, default 30, clamped 1..365. */
export function getGatewayTokenTtlDays(): number {
  const raw = process.env.GATEWAY_TOKEN_TTL_DAYS;
  if (raw === undefined) {
    return DEFAULT_TTL_DAYS;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    return DEFAULT_TTL_DAYS;
  }
  return Math.min(MAX_TTL_DAYS, Math.max(MIN_TTL_DAYS, Math.floor(parsed)));
}

/**
 * Issue a gateway token for an already-verified email + API key pair.
 * Returns undefined when the feature is not configured or the inputs are
 * outside the accepted bounds. Never logs the email, key, or token.
 */
export function issueGatewayToken(input: GatewayTokenIssueInput): string | undefined {
  const key = deriveGatewayTokenKey();
  if (!key) {
    logger.debug("Gateway token issuance skipped", { reason: "feature_disabled" });
    return undefined;
  }
  if (
    typeof input.email !== "string" ||
    input.email.length === 0 ||
    input.email.length > MAX_EMAIL_LENGTH ||
    typeof input.apiKey !== "string" ||
    input.apiKey.length === 0 ||
    input.apiKey.length > MAX_API_KEY_LENGTH
  ) {
    logger.warn("Gateway token issuance refused", { reason: "invalid_input" });
    return undefined;
  }

  const nowMs = input.now ?? Date.now();
  const iat = Math.floor(nowMs / 1000);
  const payload: GatewayTokenPayload = {
    v: TOKEN_VERSION,
    email: input.email,
    apiKey: input.apiKey,
    iat,
    exp: iat + getGatewayTokenTtlDays() * SECONDS_PER_DAY,
    jti: randomUUID(),
  };

  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(payload), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const token = GATEWAY_TOKEN_PREFIX + Buffer.concat([iv, ciphertext, tag]).toString("base64url");
  logger.info("Gateway token issued", { jti: payload.jti, exp: payload.exp });
  return token;
}

function isValidPayload(payload: unknown): payload is GatewayTokenPayload {
  if (payload === null || typeof payload !== "object") {
    return false;
  }
  const candidate = payload as Record<string, unknown>;
  return (
    candidate.v === TOKEN_VERSION &&
    typeof candidate.email === "string" &&
    candidate.email.length > 0 &&
    candidate.email.length <= MAX_EMAIL_LENGTH &&
    typeof candidate.apiKey === "string" &&
    candidate.apiKey.length > 0 &&
    candidate.apiKey.length <= MAX_API_KEY_LENGTH &&
    Number.isSafeInteger(candidate.iat) &&
    Number.isSafeInteger(candidate.exp) &&
    typeof candidate.jti === "string" &&
    candidate.jti.length > 0 &&
    candidate.jti.length <= 64
  );
}

/**
 * Parse and verify a gateway token. ANY defect (bad prefix, bad base64url,
 * truncated bytes, GCM tag mismatch, bad JSON, wrong version, missing
 * fields, expired) returns undefined. Fail closed everywhere.
 */
export function parseGatewayToken(token: string, now?: number): GatewayTokenClaims | undefined {
  const reject = (reason: string): undefined => {
    logger.debug("Gateway token rejected", { reason });
    return undefined;
  };

  if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH) {
    return reject("malformed");
  }
  if (!token.startsWith(GATEWAY_TOKEN_PREFIX)) {
    return reject("bad_prefix");
  }
  const key = deriveGatewayTokenKey();
  if (!key) {
    return reject("feature_disabled");
  }
  const encoded = token.slice(GATEWAY_TOKEN_PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.length % 4 === 1) {
    return reject("bad_base64url");
  }

  let raw: Buffer;
  try {
    raw = Buffer.from(encoded, "base64url");
  } catch {
    return reject("bad_base64url");
  }
  if (raw.length <= IV_BYTES + TAG_BYTES) {
    return reject("truncated");
  }

  const iv = raw.subarray(0, IV_BYTES);
  const tag = raw.subarray(raw.length - TAG_BYTES);
  const ciphertext = raw.subarray(IV_BYTES, raw.length - TAG_BYTES);

  let plaintext: string;
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    return reject("gcm_mismatch");
  }

  let payload: unknown;
  try {
    payload = JSON.parse(plaintext);
  } catch {
    return reject("bad_json");
  }
  if (!isValidPayload(payload)) {
    return reject("bad_payload");
  }

  const nowSeconds = Math.floor((now ?? Date.now()) / 1000);
  if (payload.exp <= nowSeconds) {
    return reject("expired");
  }

  return { email: payload.email, apiKey: payload.apiKey, exp: payload.exp, jti: payload.jti };
}

/**
 * Find the gateway-token candidate in a request's credential channels:
 * the x-api-key value when it carries the gt1. prefix, else the
 * Authorization Bearer value when it does. Mirrors the precedence in
 * authorizeInitialize: a gt1. Bearer value is a gateway token, never a
 * raw Dokploy API key.
 */
export function extractGatewayTokenCandidate(
  clientApiKey: string | undefined,
  authorization: string | undefined,
): string | undefined {
  if (clientApiKey?.startsWith(GATEWAY_TOKEN_PREFIX)) {
    return clientApiKey;
  }
  if (authorization?.startsWith("Bearer ")) {
    const bearer = authorization.slice("Bearer ".length).trim();
    if (bearer.startsWith(GATEWAY_TOKEN_PREFIX)) {
      return bearer;
    }
  }
  return undefined;
}
