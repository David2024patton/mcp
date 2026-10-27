/**
 * One-time gateway-token enrollment for single-credential MCP clients.
 *
 * Logger: createLogger("gateway-enroll"). Records are structured JSON on
 * stderr; raise verbosity by filtering the service logs for that service
 * name (the repository logger emits debug records through the same sink).
 * Main failure modes: Dokploy unreachable (503, fail closed), a rejected
 * account login or API key (one generic 401 page, never saying which),
 * a bad or stale form nonce (400), and per-IP attempt flooding (429).
 *
 * Surface and authentication: GET /enroll serves a public form, POST
 * /enroll is the enrollment action. Neither is reachable unless
 * MCP_GATEWAY_TOKEN_ENROLLMENT=1 AND GATEWAY_TOKEN_SECRET is set; the
 * register function below adds no routes otherwise, so both 404. The
 * POST is authenticated by the submitted Dokploy credentials themselves:
 * no token is issued until the account login verifies live against
 * Dokploy AND the API key proves itself against Dokploy's project list.
 * A hidden HMAC nonce (10-minute window) plus a per-IP attempt throttle
 * bound abuse of the form. The password, API key, and issued token are
 * never logged; only outcome + reason codes are.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import type { Context, Env, Hono } from "hono";
import { type AccountLoginVerification, verifyDokployAccountLogin } from "./utils/accountAuth.js";
import { getClientConfig } from "./utils/clientConfig.js";
import {
  isGatewayTokenConfigured,
  issueGatewayToken,
  parseGatewayToken,
} from "./utils/gatewayToken.js";
import { createLogger } from "./utils/logger.js";

const logger = createLogger("gateway-enroll");

const NONCE_WINDOW_MS = 10 * 60 * 1000;
const THROTTLE_WINDOW_MS = 10 * 60 * 1000;
const THROTTLE_MAX_ATTEMPTS = 10;
const THROTTLE_MAX_ENTRIES = 10_000;
const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 1024;
const MAX_API_KEY_LENGTH = 512;
const GENERIC_CREDENTIAL_FAILURE =
  "Enrollment failed. Check your Dokploy email, password, and API key.";

type ApiKeyVerification = "verified" | "rejected" | "unavailable";

export interface GatewayEnrollmentOptions {
  /** Bare Dokploy origin (no /api suffix). Defaults to the configured DOKPLOY_URL. */
  dokployUrl?: string;
  /** Fetch implementation, injectable for tests. Defaults to global fetch. */
  fetchFn?: typeof fetch;
  /** Account-login verifier, injectable for tests. Defaults to verifyDokployAccountLogin. */
  verifyFn?: (email: string, password: string) => Promise<AccountLoginVerification>;
  /** API-key checker, injectable for tests. Defaults to a project.all probe. */
  apiKeyCheckFn?: (apiKey: string) => Promise<ApiKeyVerification>;
  /** Clock, injectable for tests. Defaults to Date.now. */
  now?: () => number;
  /** Upstream request timeout in milliseconds. Defaults to 10000. */
  timeoutMs?: number;
}

/** Whether enrollment routes may be registered at all. */
export function isGatewayEnrollmentEnabled(): boolean {
  return process.env.MCP_GATEWAY_TOKEN_ENROLLMENT === "1" && isGatewayTokenConfigured();
}

function nonceForWindow(windowIndex: number, secret: string): string {
  return createHmac("sha256", secret).update(`gateway-enroll:${windowIndex}`).digest("hex");
}

/** Create the hidden form nonce for the current 10-minute window. */
export function createEnrollmentNonce(now: number = Date.now()): string {
  const secret = process.env.GATEWAY_TOKEN_SECRET;
  if (!secret) {
    return "";
  }
  return nonceForWindow(Math.floor(now / NONCE_WINDOW_MS), secret);
}

/** Accept a nonce from the current or the previous 10-minute window. */
export function isEnrollmentNonceValid(
  nonce: string | undefined,
  now: number = Date.now(),
): boolean {
  const secret = process.env.GATEWAY_TOKEN_SECRET;
  if (!secret || !nonce || !/^[a-f0-9]{64}$/.test(nonce)) {
    return false;
  }
  const currentWindow = Math.floor(now / NONCE_WINDOW_MS);
  const provided = Buffer.from(nonce, "hex");
  for (const windowIndex of [currentWindow, currentWindow - 1]) {
    const expected = Buffer.from(nonceForWindow(windowIndex, secret), "hex");
    if (expected.length === provided.length && timingSafeEqual(expected, provided)) {
      return true;
    }
  }
  return false;
}

interface ThrottleEntry {
  windowStart: number;
  count: number;
}

function pruneThrottleEntries(attempts: Map<string, ThrottleEntry>, now: number): void {
  for (const [ip, entry] of attempts) {
    if (now - entry.windowStart >= THROTTLE_WINDOW_MS) {
      attempts.delete(ip);
    }
  }
  if (attempts.size > THROTTLE_MAX_ENTRIES) {
    const oldestFirst = [...attempts.entries()].sort((a, b) => a[1].windowStart - b[1].windowStart);
    for (const [ip] of oldestFirst) {
      if (attempts.size <= THROTTLE_MAX_ENTRIES) {
        break;
      }
      attempts.delete(ip);
    }
  }
}

/**
 * Record one POST attempt for an IP. Returns false when the IP has used
 * up its attempts in the current window. Expired windows are pruned on
 * every call and the map is hard-capped, so it cannot grow unboundedly.
 */
function recordAttempt(attempts: Map<string, ThrottleEntry>, ip: string, now: number): boolean {
  pruneThrottleEntries(attempts, now);
  let entry = attempts.get(ip);
  if (!entry || now - entry.windowStart >= THROTTLE_WINDOW_MS) {
    entry = { windowStart: now, count: 0 };
    attempts.set(ip, entry);
  }
  entry.count += 1;
  return entry.count <= THROTTLE_MAX_ATTEMPTS;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const PAGE_STYLE = `
  body { background:#101014; color:#f2f2f5; font-family:system-ui,sans-serif; margin:0; }
  main { max-width:34rem; margin:3rem auto; padding:0 1.25rem; }
  label { display:block; margin:1rem 0 .35rem; font-weight:600; }
  input, textarea { width:100%; box-sizing:border-box; padding:.65rem; border-radius:.5rem;
    border:1px solid #3a3a44; background:#1a1a21; color:#f2f2f5; }
  button { margin-top:1.25rem; padding:.7rem 1.2rem; border:0; border-radius:.5rem;
    background:#4f7cff; color:#fff; font-weight:700; cursor:pointer; }
  .note { color:#b9b9c4; line-height:1.5; }
  .error { color:#ff9c9c; line-height:1.5; }
`;

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${PAGE_STYLE}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>`;
}

function respond<E extends Env>(
  c: Context<E>,
  status: 200 | 400 | 401 | 429 | 503,
  title: string,
  body: string,
) {
  c.header("Cache-Control", "no-store");
  c.header(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'self'",
  );
  c.header("X-Content-Type-Options", "nosniff");
  return c.html(page(title, body), status);
}

function failurePage<E extends Env>(c: Context<E>, status: 400 | 401 | 429 | 503, message: string) {
  return respond(
    c,
    status,
    "Dokploy gateway enrollment",
    `<h1>Enrollment</h1>
<p class="error">${escapeHtml(message)}</p>`,
  );
}

function stringField(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function clientIp<E extends Env>(c: Context<E>): string {
  const bindings = c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined;
  const remoteAddress = bindings?.incoming?.socket?.remoteAddress;
  if (remoteAddress) {
    return remoteAddress;
  }
  const forwarded = c.req.header("x-forwarded-for")?.split(",")[0]?.trim();
  return forwarded && forwarded.length > 0 ? forwarded : "unknown";
}

/**
 * Register the enrollment routes on the HTTP app. Adds NOTHING (and
 * returns false) unless enrollment is enabled and a token secret is
 * configured, so the routes 404 in every other configuration.
 */
export function registerGatewayEnrollment<E extends Env>(
  app: Hono<E>,
  options: GatewayEnrollmentOptions = {},
): boolean {
  if (!isGatewayEnrollmentEnabled()) {
    logger.debug("Gateway enrollment routes not registered", { reason: "feature_disabled" });
    return false;
  }

  const fetchFn = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const nowFn = options.now ?? Date.now;
  const attempts = new Map<string, ThrottleEntry>();

  const resolveDokployUrl = (): string | undefined => {
    if (options.dokployUrl) {
      return options.dokployUrl.replace(/\/+$/, "");
    }
    try {
      return getClientConfig().dokployUrl.replace(/\/+$/, "");
    } catch {
      return undefined;
    }
  };

  const verifyApiKey = async (apiKey: string): Promise<ApiKeyVerification> => {
    if (options.apiKeyCheckFn) {
      return options.apiKeyCheckFn(apiKey);
    }
    const dokployUrl = resolveDokployUrl();
    if (!dokployUrl) {
      return "unavailable";
    }
    const startedAt = Date.now();
    try {
      const response = await fetchFn(`${dokployUrl}/api/project.all`, {
        method: "GET",
        headers: { "x-api-key": apiKey, Accept: "application/json" },
        signal: AbortSignal.timeout(timeoutMs),
        redirect: "manual",
      });
      logger.debug("Dokploy API key check completed", {
        status: response.status,
        durationMs: Date.now() - startedAt,
      });
      return response.status === 200 ? "verified" : "rejected";
    } catch {
      logger.debug("Dokploy API key check failed", {
        reason: "unreachable",
        durationMs: Date.now() - startedAt,
      });
      return "unavailable";
    }
  };

  app.get("/enroll", (c) => {
    const nonce = createEnrollmentNonce(nowFn());
    logger.debug("Enrollment form served", { outcome: "form_served" });
    return respond(
      c,
      200,
      "Dokploy gateway enrollment",
      `<h1>Dokploy gateway enrollment</h1>
<p class="note">Enter your Dokploy account email, password, and API key once.
The gateway checks both, then issues a single gateway token for your MCP
client. Your password is checked once and never stored.</p>
<form method="post" action="/enroll">
<input type="hidden" name="nonce" value="${escapeHtml(nonce)}">
<label for="email">Dokploy email</label>
<input id="email" name="email" type="email" autocomplete="username" required maxlength="254">
<label for="password">Dokploy password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<label for="apiKey">Dokploy API key</label>
<input id="apiKey" name="apiKey" type="password" autocomplete="off" required>
<button type="submit">Create gateway token</button>
</form>`,
    );
  });

  app.post("/enroll", async (c) => {
    const now = nowFn();
    if (!recordAttempt(attempts, clientIp(c), now)) {
      logger.warn("Enrollment refused", { outcome: "failure", reason: "rate_limited" });
      return failurePage(c, 429, "Too many enrollment attempts. Wait a few minutes and try again.");
    }

    const contentType = c.req.header("content-type") ?? "";
    if (!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
      logger.warn("Enrollment refused", { outcome: "failure", reason: "bad_content_type" });
      return failurePage(c, 400, "Enrollment failed.");
    }

    let body: Record<string, unknown>;
    try {
      body = (await c.req.parseBody()) as Record<string, unknown>;
    } catch {
      logger.warn("Enrollment refused", { outcome: "failure", reason: "bad_body" });
      return failurePage(c, 400, "Enrollment failed.");
    }

    if (!isEnrollmentNonceValid(stringField(body.nonce), now)) {
      logger.warn("Enrollment refused", { outcome: "failure", reason: "bad_nonce" });
      return failurePage(c, 400, "Enrollment failed.");
    }

    const email = stringField(body.email)?.trim() ?? "";
    const password = stringField(body.password) ?? "";
    const apiKey = stringField(body.apiKey) ?? "";
    if (
      email.length === 0 ||
      email.length > MAX_EMAIL_LENGTH ||
      password.length === 0 ||
      password.length > MAX_PASSWORD_LENGTH ||
      apiKey.length === 0 ||
      apiKey.length > MAX_API_KEY_LENGTH
    ) {
      logger.warn("Enrollment refused", { outcome: "failure", reason: "invalid_fields" });
      return failurePage(c, 400, "Enrollment failed.");
    }

    let loginOutcome: AccountLoginVerification;
    try {
      if (options.verifyFn) {
        loginOutcome = await options.verifyFn(email, password);
      } else {
        const dokployUrl = resolveDokployUrl();
        loginOutcome = await verifyDokployAccountLogin(email, password, {
          fetchFn,
          timeoutMs,
          ...(dokployUrl ? { dokployUrl } : {}),
        });
      }
    } catch {
      loginOutcome = "unavailable";
    }
    if (loginOutcome === "rejected") {
      logger.warn("Enrollment refused", { outcome: "failure", reason: "login_rejected" });
      return failurePage(c, 401, GENERIC_CREDENTIAL_FAILURE);
    }
    if (loginOutcome === "unavailable") {
      logger.error("Enrollment failed", { outcome: "failure", reason: "dokploy_unavailable" });
      return failurePage(c, 503, "Enrollment is temporarily unavailable. Try again later.");
    }

    let apiKeyOutcome: ApiKeyVerification;
    try {
      apiKeyOutcome = await verifyApiKey(apiKey);
    } catch {
      apiKeyOutcome = "unavailable";
    }
    if (apiKeyOutcome === "rejected") {
      logger.warn("Enrollment refused", { outcome: "failure", reason: "api_key_rejected" });
      return failurePage(c, 401, GENERIC_CREDENTIAL_FAILURE);
    }
    if (apiKeyOutcome === "unavailable") {
      logger.error("Enrollment failed", { outcome: "failure", reason: "dokploy_unavailable" });
      return failurePage(c, 503, "Enrollment is temporarily unavailable. Try again later.");
    }

    const token = issueGatewayToken({ email, apiKey, now: nowFn() });
    if (!token) {
      logger.error("Enrollment failed", { outcome: "failure", reason: "token_issue_failed" });
      return failurePage(c, 503, "Enrollment is temporarily unavailable. Try again later.");
    }
    const claims = parseGatewayToken(token, nowFn());
    const expiryDate = claims ? new Date(claims.exp * 1000).toISOString().slice(0, 10) : "";
    logger.info("Enrollment completed", {
      outcome: "success",
      reason: "issued",
      ...(claims ? { exp: claims.exp } : {}),
    });

    return respond(
      c,
      200,
      "Dokploy gateway enrollment",
      `<h1>Your gateway token</h1>
<p class="note">This token is shown once. It expires on ${escapeHtml(expiryDate)}.</p>
<label for="gateway-token">Gateway token</label>
<textarea id="gateway-token" readonly rows="5">${escapeHtml(token)}</textarea>
<button type="button" id="copy-token">Copy token</button>
<ul class="note">
<li>Put this token in your Muse connector's credential field. It replaces the Dokploy API key there; the server URL stays the same.</li>
<li>Never paste the token into chat.</li>
<li>When it expires, come back to this page and enroll again.</li>
</ul>
<script>
document.getElementById("copy-token").addEventListener("click", async () => {
  const field = document.getElementById("gateway-token");
  field.select();
  try { await navigator.clipboard.writeText(field.value); } catch { document.execCommand("copy"); }
});
</script>`,
    );
  });

  logger.info("Gateway enrollment routes registered", { outcome: "registered" });
  return true;
}
