/**
 * Dokploy account-login verification for hosted HTTP mode.
 *
 * When MCP_REQUIRE_ACCOUNT_LOGIN=1, opening a session requires THREE
 * things together: the gateway URL, the caller's own Dokploy API key
 * (existing passthrough, see requestAuth.ts), AND the caller's own
 * Dokploy account login (email + account password), verified live
 * against Dokploy at connect time.
 *
 * Credential channels are kept strictly separate:
 * - The API key arrives in the "x-api-key" header, or in "Authorization"
 *   only when it uses the Bearer scheme.
 * - The account login arrives ONLY as "Authorization: Basic
 *   base64(email:password)". A Basic value is never treated as an API
 *   key, and a Bearer value is never treated as account credentials.
 *
 * The password is used exactly once, inside the sign-in verification
 * call, and is never stored or logged. Only a boolean outcome and the
 * account email may be kept per session.
 */

import { getClientConfig } from "./clientConfig.js";

export interface AccountCredentials {
  email: string;
  password: string;
}

export type AccountLoginVerification = "verified" | "rejected" | "unavailable";

export interface VerifyOptions {
  /** Bare Dokploy origin (no /api suffix). Defaults to the configured DOKPLOY_URL. */
  dokployUrl?: string;
  /** Fetch implementation, injectable for tests. Defaults to global fetch. */
  fetchFn?: typeof fetch;
  /** Sign-in request timeout in milliseconds. Defaults to 10000. */
  timeoutMs?: number;
}

export interface InitializeAuthorization {
  allowed: boolean;
  /** HTTP status to return when not allowed. */
  status?: 401 | 503;
  /** Client-facing error message when not allowed. */
  message?: string;
  /** The verified account email, present only when a login was verified. */
  email?: string;
}

const MISSING_KEY_MESSAGE =
  "Unauthorized: this gateway requires your own Dokploy API key. Send it in the 'x-api-key' header (or as 'Authorization: Bearer <key>').";
const MISSING_LOGIN_MESSAGE =
  "Unauthorized: this gateway requires your Dokploy account login. Send it as 'Authorization: Basic <base64(email:password)>'.";
const REJECTED_LOGIN_MESSAGE = "Unauthorized: the Dokploy account login was rejected.";
const UNAVAILABLE_MESSAGE =
  "Account login verification is unavailable: Dokploy could not be reached. Try again later.";

/** Whether the account-login check is enabled (MCP_REQUIRE_ACCOUNT_LOGIN=1). */
export function isAccountLoginRequired(): boolean {
  return process.env.MCP_REQUIRE_ACCOUNT_LOGIN === "1";
}

/** Whether a per-request client API key is required (MCP_REQUIRE_CLIENT_KEY=1). */
export function isClientKeyRequired(): boolean {
  return process.env.MCP_REQUIRE_CLIENT_KEY === "1";
}

/**
 * Parse an "Authorization: Basic base64(email:password)" header value.
 * Returns undefined for anything missing or malformed: wrong scheme,
 * invalid base64, no colon separator, or an empty email or password.
 * A Bearer value (or any other scheme) is never parsed as credentials.
 */
export function parseBasicAuthCredentials(
  authorization: string | undefined,
): AccountCredentials | undefined {
  if (!authorization) {
    return undefined;
  }
  const match = /^Basic ([A-Za-z0-9+/=]+)$/i.exec(authorization.trim());
  if (!match) {
    return undefined;
  }
  const encoded = match[1];
  if (!encoded || encoded.length % 4 === 1) {
    return undefined;
  }
  let decoded: string;
  try {
    decoded = Buffer.from(encoded, "base64").toString("utf8");
  } catch {
    return undefined;
  }
  const separator = decoded.indexOf(":");
  if (separator <= 0) {
    return undefined;
  }
  const email = decoded.slice(0, separator);
  const password = decoded.slice(separator + 1);
  if (email.length === 0 || password.length === 0) {
    return undefined;
  }
  return { email, password };
}

function hasSessionCookie(headers: Headers): boolean {
  const cookies =
    typeof headers.getSetCookie === "function"
      ? headers.getSetCookie()
      : [headers.get("set-cookie") ?? ""];
  // better-auth sets a session cookie named e.g. "better-auth.session_token"
  // (possibly with a "__Secure-" prefix). An account with two-factor auth
  // enabled gets HTTP 200 with a twoFactorRedirect body and NO session
  // cookie; that is not a completed sign-in, so it counts as rejected.
  return cookies.some((cookie) => /session_token=[^;\s]+/.test(cookie));
}

/**
 * Verify a Dokploy account login by attempting a real sign-in against
 * Dokploy's better-auth endpoint: POST {DOKPLOY_URL}/api/auth/sign-in/email
 * (Dokploy v0.30.x mounts the better-auth handler under /api/auth, with
 * emailAndPassword enabled; verified against the Dokploy v0.30.10 source:
 * apps/dokploy/pages/api/auth/[...all].ts and packages/server/src/lib/auth.ts).
 * DOKPLOY_URL is the bare origin; the /api/auth path is appended here, NOT
 * via the API client (whose baseURL already adds /api for API routes).
 *
 * Outcomes:
 * - "verified": HTTP 200 with a session cookie set.
 * - "rejected": any other response, including 200 without a session
 *   cookie (two-factor redirect) and 401 invalid credentials.
 * - "unavailable": Dokploy could not be reached (network error/timeout).
 *   Callers must fail closed on this outcome.
 *
 * The password travels only inside this call's request body. It is never
 * stored, returned, or logged.
 */
export async function verifyDokployAccountLogin(
  email: string,
  password: string,
  options: VerifyOptions = {},
): Promise<AccountLoginVerification> {
  const dokployUrl = (options.dokployUrl ?? getClientConfig().dokployUrl).replace(/\/+$/, "");
  const fetchFn = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;

  let response: Response;
  try {
    response = await fetchFn(`${dokployUrl}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ email, password }),
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "manual",
    });
  } catch {
    return "unavailable";
  }

  if (response.status === 200 && hasSessionCookie(response.headers)) {
    return "verified";
  }
  return "rejected";
}

export interface AuthorizeInitializeInput {
  /** The caller's Dokploy API key as extracted from the request, if any. */
  clientApiKey: string | undefined;
  /** The raw Authorization header value, if any. */
  authorization: string | undefined;
}

export interface AuthorizeInitializeOptions {
  /** Sign-in verifier, injectable for tests. Defaults to verifyDokployAccountLogin. */
  verifyFn?: (email: string, password: string) => Promise<AccountLoginVerification>;
}

/**
 * Decide whether an initialize request may open a session.
 *
 * Order of checks:
 * 1. With MCP_REQUIRE_CLIENT_KEY=1, a missing API key is refused (401),
 *    exactly as the gateway behaved before this feature.
 * 2. With MCP_REQUIRE_ACCOUNT_LOGIN=1, missing or malformed Basic
 *    credentials are refused (401); a Dokploy-rejected login is refused
 *    (401); if Dokploy cannot be reached to verify the login, the
 *    gateway fails closed (503, no session).
 * 3. With the login flag off, behavior is exactly as before: the login
 *    is not consulted at all.
 */
export async function authorizeInitialize(
  input: AuthorizeInitializeInput,
  options: AuthorizeInitializeOptions = {},
): Promise<InitializeAuthorization> {
  if (isClientKeyRequired() && !input.clientApiKey) {
    return { allowed: false, status: 401, message: MISSING_KEY_MESSAGE };
  }

  if (!isAccountLoginRequired()) {
    return { allowed: true };
  }

  const credentials = parseBasicAuthCredentials(input.authorization);
  if (!credentials) {
    return { allowed: false, status: 401, message: MISSING_LOGIN_MESSAGE };
  }

  const verifyFn = options.verifyFn ?? verifyDokployAccountLogin;
  const outcome = await verifyFn(credentials.email, credentials.password);
  if (outcome === "verified") {
    return { allowed: true, email: credentials.email };
  }
  if (outcome === "unavailable") {
    return { allowed: false, status: 503, message: UNAVAILABLE_MESSAGE };
  }
  return { allowed: false, status: 401, message: REJECTED_LOGIN_MESSAGE };
}
