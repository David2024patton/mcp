import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createEnrollmentNonce,
  isEnrollmentNonceValid,
  registerGatewayEnrollment,
} from "./enroll.js";
import { parseGatewayToken } from "./utils/gatewayToken.js";

const ENV_KEYS = [
  "MCP_GATEWAY_TOKEN_ENROLLMENT",
  "GATEWAY_TOKEN_SECRET",
  "GATEWAY_TOKEN_TTL_DAYS",
] as const;
const savedEnv: Record<string, string | undefined> = {};
for (const key of ENV_KEYS) {
  savedEnv[key] = process.env[key];
}

const EMAIL = "user@example.com";
const PASSWORD = "fake-enroll-password-9f3";
const API_KEY = "fake-enroll-api-key-7c1";
const GENERIC_FAILURE = "Enrollment failed. Check your Dokploy email, password, and API key.";

beforeEach(() => {
  process.env.MCP_GATEWAY_TOKEN_ENROLLMENT = "1";
  process.env.GATEWAY_TOKEN_SECRET = "enroll-test-secret";
  delete process.env.GATEWAY_TOKEN_TTL_DAYS;
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = savedEnv[key];
    }
  }
  vi.restoreAllMocks();
});

function fakeResponse(status: number, cookies: string[] = []): Response {
  const headers = new Headers();
  for (const cookie of cookies) {
    headers.append("set-cookie", cookie);
  }
  return { status, headers } as unknown as Response;
}

function fetchWith({
  signInStatus = 200,
  projectStatus = 200,
  unreachable = false,
}: {
  signInStatus?: number;
  projectStatus?: number;
  unreachable?: boolean;
} = {}): typeof fetch {
  return vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    if (unreachable) {
      throw new Error("connect ECONNREFUSED");
    }
    const target = String(url);
    if (target.endsWith("/api/auth/sign-in/email")) {
      const cookies =
        signInStatus === 200 ? ["better-auth.session_token=fake-token; Path=/; HttpOnly"] : [];
      return fakeResponse(signInStatus, cookies);
    }
    if (target.endsWith("/api/project.all")) {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      expect(headers["x-api-key"]).toBe(API_KEY);
      return fakeResponse(projectStatus);
    }
    throw new Error(`unexpected fetch target: ${target}`);
  }) as unknown as typeof fetch;
}

function buildApp(fetchFn: typeof fetch, now?: () => number): Hono {
  const app = new Hono();
  const registered = registerGatewayEnrollment(app, {
    dokployUrl: "https://dokploy.example",
    fetchFn,
    ...(now ? { now } : {}),
  });
  expect(registered).toBe(true);
  return app;
}

async function getNonce(app: Hono): Promise<string> {
  const response = await app.request("http://localhost/enroll");
  expect(response.status).toBe(200);
  expect(response.headers.get("cache-control")).toBe("no-store");
  const html = await response.text();
  const nonce = /name="nonce" value="([a-f0-9]{64})"/.exec(html)?.[1];
  if (!nonce) {
    throw new Error("enrollment form did not carry a nonce");
  }
  return nonce;
}

function postEnroll(app: Hono, fields: Record<string, string>): Promise<Response> {
  return app.request("http://localhost/enroll", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });
}

const validFields = (nonce: string) => ({
  nonce,
  email: EMAIL,
  password: PASSWORD,
  apiKey: API_KEY,
});

describe("gateway enrollment routes", () => {
  it("serves a dark, self-contained form with a nonce and no-store caching", async () => {
    const app = buildApp(fetchWith());
    const response = await app.request("http://localhost/enroll");
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(html).toContain('name="email"');
    expect(html).toContain('name="password"');
    expect(html).toContain('name="apiKey"');
    expect(html).toContain('name="nonce"');
    expect(html).not.toContain("http://");
    expect(html).not.toContain("https://");
  });

  it("does not register the routes when enrollment is disabled or the secret is missing", async () => {
    delete process.env.MCP_GATEWAY_TOKEN_ENROLLMENT;
    const appWithoutFlag = new Hono();
    expect(registerGatewayEnrollment(appWithoutFlag)).toBe(false);
    expect((await appWithoutFlag.request("http://localhost/enroll")).status).toBe(404);

    process.env.MCP_GATEWAY_TOKEN_ENROLLMENT = "1";
    delete process.env.GATEWAY_TOKEN_SECRET;
    const appWithoutSecret = new Hono();
    expect(registerGatewayEnrollment(appWithoutSecret)).toBe(false);
    expect((await appWithoutSecret.request("http://localhost/enroll")).status).toBe(404);
  });

  it("accepts a nonce from the previous 10-minute window", () => {
    const now = Date.now();
    const previousWindowNonce = createEnrollmentNonce(now - 10 * 60 * 1000);
    expect(isEnrollmentNonceValid(previousWindowNonce, now)).toBe(true);
    expect(isEnrollmentNonceValid("0".repeat(64), now)).toBe(false);
    expect(isEnrollmentNonceValid(undefined, now)).toBe(false);
  });

  it("issues a parseable gateway token carrying the submitted API key on success", async () => {
    const app = buildApp(fetchWith());
    const nonce = await getNonce(app);

    const response = await postEnroll(app, validFields(nonce));
    const html = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const token = /gt1\.[A-Za-z0-9_-]+/.exec(html)?.[0];
    if (!token) {
      throw new Error("success page did not show a gateway token");
    }
    const claims = parseGatewayToken(token);
    expect(claims?.email).toBe(EMAIL);
    expect(claims?.apiKey).toBe(API_KEY);
    expect(html).toContain("expires on");
    expect(html).toContain("Never paste the token into chat");
  });

  it("refuses a rejected login with the single generic line", async () => {
    const app = buildApp(fetchWith({ signInStatus: 401 }));
    const nonce = await getNonce(app);

    const response = await postEnroll(app, validFields(nonce));
    const html = await response.text();

    expect(response.status).toBe(401);
    expect(html).toContain(GENERIC_FAILURE);
    expect(html).not.toContain("password was wrong");
    expect(html).not.toContain("login rejected");
  });

  it("refuses a bad API key with the same generic line", async () => {
    const app = buildApp(fetchWith({ projectStatus: 401 }));
    const nonce = await getNonce(app);

    const response = await postEnroll(app, validFields(nonce));
    const html = await response.text();

    expect(response.status).toBe(401);
    expect(html).toContain(GENERIC_FAILURE);
  });

  it("fails with 503 when Dokploy cannot be reached", async () => {
    const app = buildApp(fetchWith({ unreachable: true }));
    const nonce = await getNonce(app);

    const response = await postEnroll(app, validFields(nonce));

    expect(response.status).toBe(503);
  });

  it("refuses a bad nonce and missing fields with a generic 400", async () => {
    const app = buildApp(fetchWith());

    const badNonce = await postEnroll(app, validFields("0".repeat(64)));
    expect(badNonce.status).toBe(400);

    const nonce = await getNonce(app);
    const missing = await postEnroll(app, { nonce, email: EMAIL });
    expect(missing.status).toBe(400);
    const missingHtml = await missing.text();
    expect(missingHtml).not.toContain("apiKey");
  });

  it("throttles the 11th POST attempt inside the window with 429", async () => {
    const app = buildApp(fetchWith());
    let lastStatus = 0;
    for (let attempt = 1; attempt <= 11; attempt += 1) {
      const response = await postEnroll(app, validFields("0".repeat(64)));
      lastStatus = response.status;
      if (attempt <= 10) {
        expect(lastStatus, `attempt ${attempt}`).toBe(400);
      }
    }
    expect(lastStatus).toBe(429);
  });

  it("never writes the password, API key, or issued token to the logs", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const successApp = buildApp(fetchWith());
    const successNonce = await getNonce(successApp);
    const success = await postEnroll(successApp, validFields(successNonce));
    expect(success.status).toBe(200);
    const successHtml = await success.text();
    const token = /gt1\.[A-Za-z0-9_-]+/.exec(successHtml)?.[0];
    if (!token) {
      throw new Error("success page did not show a gateway token");
    }

    const failureApp = buildApp(fetchWith({ signInStatus: 401 }));
    const failureNonce = await getNonce(failureApp);
    const failure = await postEnroll(failureApp, validFields(failureNonce));
    expect(failure.status).toBe(401);

    const logged = errorSpy.mock.calls.map((call) => call.map(String).join(" ")).join("\n");
    expect(logged).toContain("gateway-enroll");
    expect(logged).not.toContain(PASSWORD);
    expect(logged).not.toContain(API_KEY);
    expect(logged).not.toContain(token);
  });
});
