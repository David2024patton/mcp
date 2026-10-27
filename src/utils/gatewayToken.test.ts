import { afterEach, describe, expect, it } from "vitest";
import {
  extractGatewayTokenCandidate,
  issueGatewayToken,
  parseGatewayToken,
} from "./gatewayToken.js";

const ENV_KEYS = ["GATEWAY_TOKEN_SECRET", "GATEWAY_TOKEN_TTL_DAYS"] as const;
const savedEnv: Record<string, string | undefined> = {};
for (const key of ENV_KEYS) {
  savedEnv[key] = process.env[key];
}

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = savedEnv[key];
    }
  }
});

const NOW = 1_700_000_000_000; // fixed instant, milliseconds
const NOW_SECONDS = Math.floor(NOW / 1000);
const EMAIL = "user@example.com";
const API_KEY = "caller-api-key-for-tests";

function issue(now: number = NOW): string {
  const token = issueGatewayToken({ email: EMAIL, apiKey: API_KEY, now });
  if (!token) {
    throw new Error("expected a token to be issued");
  }
  return token;
}

describe("gatewayToken", () => {
  it("roundtrips email, API key, expiry, and jti", () => {
    process.env.GATEWAY_TOKEN_SECRET = "unit-test-secret";
    delete process.env.GATEWAY_TOKEN_TTL_DAYS;

    const token = issue();
    expect(token.startsWith("gt1.")).toBe(true);

    const claims = parseGatewayToken(token, NOW);
    expect(claims?.email).toBe(EMAIL);
    expect(claims?.apiKey).toBe(API_KEY);
    expect(claims?.exp).toBe(NOW_SECONDS + 30 * 86_400);
    expect(claims?.jti).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it("uses a base64 secret that decodes to exactly 32 bytes as the raw key", () => {
    process.env.GATEWAY_TOKEN_SECRET = Buffer.alloc(32, 7).toString("base64");
    const token = issue();
    expect(parseGatewayToken(token, NOW)?.apiKey).toBe(API_KEY);
  });

  it("clamps the TTL into 1..365 days and defaults invalid values to 30", () => {
    process.env.GATEWAY_TOKEN_SECRET = "unit-test-secret";

    process.env.GATEWAY_TOKEN_TTL_DAYS = "0";
    expect(parseGatewayToken(issue(), NOW)?.exp).toBe(NOW_SECONDS + 86_400);

    process.env.GATEWAY_TOKEN_TTL_DAYS = "999";
    expect(parseGatewayToken(issue(), NOW)?.exp).toBe(NOW_SECONDS + 365 * 86_400);

    process.env.GATEWAY_TOKEN_TTL_DAYS = "not-a-number";
    expect(parseGatewayToken(issue(), NOW)?.exp).toBe(NOW_SECONDS + 30 * 86_400);
  });

  it("rejects a tampered token", () => {
    process.env.GATEWAY_TOKEN_SECRET = "unit-test-secret";
    const token = issue();
    const flipAt = Math.floor(token.length / 2);
    const replacement = token[flipAt] === "A" ? "B" : "A";
    const tampered = token.slice(0, flipAt) + replacement + token.slice(flipAt + 1);
    expect(tampered).not.toBe(token);
    expect(parseGatewayToken(tampered, NOW)).toBeUndefined();
  });

  it("rejects an expired token at and after its expiry", () => {
    process.env.GATEWAY_TOKEN_SECRET = "unit-test-secret";
    process.env.GATEWAY_TOKEN_TTL_DAYS = "1";
    const token = issue();
    const expiryMs = (NOW_SECONDS + 86_400) * 1000;
    expect(parseGatewayToken(token, expiryMs - 1000)).toBeDefined();
    expect(parseGatewayToken(token, expiryMs)).toBeUndefined();
    expect(parseGatewayToken(token, expiryMs + 86_400_000)).toBeUndefined();
  });

  it("rejects a token under the wrong secret", () => {
    process.env.GATEWAY_TOKEN_SECRET = "unit-test-secret";
    const token = issue();
    process.env.GATEWAY_TOKEN_SECRET = "a-different-secret";
    expect(parseGatewayToken(token, NOW)).toBeUndefined();
  });

  it("rejects malformed strings", () => {
    process.env.GATEWAY_TOKEN_SECRET = "unit-test-secret";
    for (const bad of [
      "",
      "gt1.",
      "gt1.!!!not-base64url!!!",
      "gt1.a",
      "not-a-gateway-token",
      `gt2.${issue().slice(4)}`,
      `${issue()}extra-padding-that-breaks-the-tag`,
    ]) {
      expect(
        parseGatewayToken(bad, NOW),
        `expected rejection: ${bad.slice(0, 24)}`,
      ).toBeUndefined();
    }
  });

  it("is disabled when the secret is missing or empty", () => {
    delete process.env.GATEWAY_TOKEN_SECRET;
    expect(issueGatewayToken({ email: EMAIL, apiKey: API_KEY, now: NOW })).toBeUndefined();

    process.env.GATEWAY_TOKEN_SECRET = "unit-test-secret";
    const token = issue();
    delete process.env.GATEWAY_TOKEN_SECRET;
    expect(parseGatewayToken(token, NOW)).toBeUndefined();

    process.env.GATEWAY_TOKEN_SECRET = "";
    expect(issueGatewayToken({ email: EMAIL, apiKey: API_KEY, now: NOW })).toBeUndefined();
  });

  it("extracts the candidate from x-api-key first, then from Bearer", () => {
    const token = "gt1.example-token";
    expect(extractGatewayTokenCandidate(token, undefined)).toBe(token);
    expect(extractGatewayTokenCandidate("raw-api-key", `Bearer ${token}`)).toBe(token);
    expect(extractGatewayTokenCandidate(token, "Bearer gt1.other-token")).toBe(token);
    expect(extractGatewayTokenCandidate("raw-api-key", "Bearer raw-api-key")).toBeUndefined();
    expect(extractGatewayTokenCandidate(undefined, "Basic abc")).toBeUndefined();
    expect(extractGatewayTokenCandidate(undefined, undefined)).toBeUndefined();
  });
});
