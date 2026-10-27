import { AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type AccountLoginVerification,
  authorizeInitialize,
  parseBasicAuthCredentials,
  verifyDokployAccountLogin,
} from "./accountAuth.js";
import { issueGatewayToken } from "./gatewayToken.js";
import { extractClientApiKey } from "./requestAuth.js";

const ENV_KEYS = [
  "DOKPLOY_URL",
  "DOKPLOY_API_KEY",
  "MCP_REQUIRE_CLIENT_KEY",
  "MCP_REQUIRE_ACCOUNT_LOGIN",
  "GATEWAY_TOKEN_SECRET",
  "GATEWAY_TOKEN_TTL_DAYS",
] as const;
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
  vi.resetModules();
});

const basic = (email: string, password: string) =>
  `Basic ${Buffer.from(`${email}:${password}`, "utf8").toString("base64")}`;

function headerGetter(headers: Record<string, string>) {
  return (name: string) => headers[name.toLowerCase()];
}

describe("parseBasicAuthCredentials", () => {
  it("parses a valid Basic header", () => {
    expect(parseBasicAuthCredentials(basic("user@example.com", "fake-password"))).toEqual({
      email: "user@example.com",
      password: "fake-password",
    });
  });

  it("keeps colons inside the password", () => {
    expect(parseBasicAuthCredentials(basic("user@example.com", "fake:pass:word"))).toEqual({
      email: "user@example.com",
      password: "fake:pass:word",
    });
  });

  it("accepts a lowercase basic scheme", () => {
    const value = basic("user@example.com", "fake-password").replace("Basic", "basic");
    expect(parseBasicAuthCredentials(value)).toEqual({
      email: "user@example.com",
      password: "fake-password",
    });
  });

  it("returns undefined when the header is missing", () => {
    expect(parseBasicAuthCredentials(undefined)).toBeUndefined();
  });

  it("returns undefined for malformed base64", () => {
    expect(parseBasicAuthCredentials("Basic not!!base64!!")).toBeUndefined();
    expect(parseBasicAuthCredentials("Basic a")).toBeUndefined();
  });

  it("returns undefined when there is no colon separator", () => {
    const value = `Basic ${Buffer.from("no-colon-here").toString("base64")}`;
    expect(parseBasicAuthCredentials(value)).toBeUndefined();
  });

  it("returns undefined for an empty email or an empty password", () => {
    expect(parseBasicAuthCredentials(basic("", "fake-password"))).toBeUndefined();
    expect(parseBasicAuthCredentials(basic("user@example.com", ""))).toBeUndefined();
  });

  it("never treats a Bearer value as account credentials", () => {
    expect(parseBasicAuthCredentials("Bearer some-api-key")).toBeUndefined();
  });
});

describe("credential channel separation", () => {
  it("never treats a Basic Authorization value as an API key", () => {
    const headers = { authorization: basic("user@example.com", "fake-password") };
    expect(extractClientApiKey(headerGetter(headers))).toBeUndefined();
  });

  it("reads the key from x-api-key even when Basic credentials are present", () => {
    const headers = {
      "x-api-key": "caller-key",
      authorization: basic("user@example.com", "fake-password"),
    };
    expect(extractClientApiKey(headerGetter(headers))).toBe("caller-key");
  });

  it("reads the key from a Bearer Authorization header", () => {
    const headers = { authorization: "Bearer caller-key" };
    expect(extractClientApiKey(headerGetter(headers))).toBe("caller-key");
  });
});

function fakeResponse(status: number, cookies: string[] = []): Response {
  const headers = new Headers();
  for (const cookie of cookies) {
    headers.append("set-cookie", cookie);
  }
  return { status, headers } as unknown as Response;
}

describe("verifyDokployAccountLogin", () => {
  it("verifies on HTTP 200 with a session cookie, calling the better-auth sign-in endpoint", async () => {
    const fetchFn = vi.fn(async () =>
      fakeResponse(200, ["better-auth.session_token=fake-token; Path=/; HttpOnly"]),
    ) as unknown as typeof fetch;

    const outcome = await verifyDokployAccountLogin("user@example.com", "fake-password", {
      dokployUrl: "https://dokploy.example/",
      fetchFn,
    });

    expect(outcome).toBe("verified");
    const [url, init] = (fetchFn as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    // Bare origin + /api/auth/sign-in/email, never a doubled /api.
    expect(url).toBe("https://dokploy.example/api/auth/sign-in/email");
    expect(init.method).toBe("POST");
    // The Dokploy origin must be sent as Origin, or better-auth answers
    // 403 MISSING_OR_NULL_ORIGIN for browser-like fetch clients.
    expect(init.headers.Origin).toBe("https://dokploy.example");
    expect(JSON.parse(init.body)).toEqual({
      email: "user@example.com",
      password: "fake-password",
    });
  });

  it("rejects when Dokploy refuses the credentials", async () => {
    const fetchFn = vi.fn(async () => fakeResponse(401)) as unknown as typeof fetch;
    const outcome = await verifyDokployAccountLogin("user@example.com", "wrong-password", {
      dokployUrl: "https://dokploy.example",
      fetchFn,
    });
    expect(outcome).toBe("rejected");
  });

  it("rejects HTTP 200 without a session cookie (two-factor redirect shape)", async () => {
    const fetchFn = vi.fn(async () => fakeResponse(200)) as unknown as typeof fetch;
    const outcome = await verifyDokployAccountLogin("user@example.com", "fake-password", {
      dokployUrl: "https://dokploy.example",
      fetchFn,
    });
    expect(outcome).toBe("rejected");
  });

  it("reports unavailable when Dokploy cannot be reached", async () => {
    const fetchFn = vi.fn(async () => {
      throw new Error("connect ECONNREFUSED");
    }) as unknown as typeof fetch;
    const outcome = await verifyDokployAccountLogin("user@example.com", "fake-password", {
      dokployUrl: "https://dokploy.example",
      fetchFn,
    });
    expect(outcome).toBe("unavailable");
  });
});

describe("authorizeInitialize", () => {
  it("allows initialize with no credentials when both flags are off", async () => {
    delete process.env.MCP_REQUIRE_CLIENT_KEY;
    delete process.env.MCP_REQUIRE_ACCOUNT_LOGIN;
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");

    const result = await authorizeInitialize(
      { clientApiKey: undefined, authorization: undefined },
      { verifyFn },
    );

    expect(result.allowed).toBe(true);
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it("behaves as before with only the client-key flag on and a key presented", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    delete process.env.MCP_REQUIRE_ACCOUNT_LOGIN;
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");

    const result = await authorizeInitialize(
      { clientApiKey: "caller-key", authorization: undefined },
      { verifyFn },
    );

    expect(result.allowed).toBe(true);
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it("refuses initialize without a key when the client-key flag is on", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");

    const result = await authorizeInitialize(
      {
        clientApiKey: undefined,
        authorization: basic("user@example.com", "fake-password"),
      },
      { verifyFn },
    );

    expect(result.allowed).toBe(false);
    expect(result.status).toBe(401);
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it("refuses initialize without Basic credentials when the login flag is on", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");

    const result = await authorizeInitialize(
      { clientApiKey: "caller-key", authorization: undefined },
      { verifyFn },
    );

    expect(result.allowed).toBe(false);
    expect(result.status).toBe(401);
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it("refuses initialize with malformed Basic credentials", async () => {
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");

    const result = await authorizeInitialize(
      { clientApiKey: "caller-key", authorization: "Basic !!!" },
      { verifyFn },
    );

    expect(result.allowed).toBe(false);
    expect(result.status).toBe(401);
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it("never uses a Bearer value as account credentials", async () => {
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");

    const result = await authorizeInitialize(
      { clientApiKey: "caller-key", authorization: "Bearer caller-key" },
      { verifyFn },
    );

    expect(result.allowed).toBe(false);
    expect(result.status).toBe(401);
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it("refuses a correct key with a wrong password", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(
      async (_email: string, _password: string): Promise<AccountLoginVerification> => "rejected",
    );

    const result = await authorizeInitialize(
      {
        clientApiKey: "caller-key",
        authorization: basic("user@example.com", "wrong-password"),
      },
      { verifyFn },
    );

    expect(result.allowed).toBe(false);
    expect(result.status).toBe(401);
    expect(verifyFn).toHaveBeenCalledWith("user@example.com", "wrong-password");
  });

  it("fails closed with 503 when Dokploy cannot be reached to verify the login", async () => {
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "unavailable");

    const result = await authorizeInitialize(
      {
        clientApiKey: "caller-key",
        authorization: basic("user@example.com", "fake-password"),
      },
      { verifyFn },
    );

    expect(result.allowed).toBe(false);
    expect(result.status).toBe(503);
  });

  it("allows initialize with a verified login and returns only the account email", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");

    const result = await authorizeInitialize(
      {
        clientApiKey: "caller-key",
        authorization: basic("user@example.com", "fake-password"),
      },
      { verifyFn },
    );

    expect(result).toEqual({ allowed: true, email: "user@example.com" });
    expect(JSON.stringify(result)).not.toContain("fake-password");
  });

  it("after a verified login, tool calls still carry the caller's API key", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");

    const gate = await authorizeInitialize(
      {
        clientApiKey: "caller-key",
        authorization: basic("user@example.com", "fake-password"),
      },
      { verifyFn },
    );
    expect(gate.allowed).toBe(true);

    process.env.DOKPLOY_URL = "https://example.com";
    process.env.DOKPLOY_API_KEY = "server-default-key";
    vi.resetModules();
    const { applyRequestAuth } = await import("./apiClient.js");
    // Re-import the storage too: after resetModules the API client closes
    // over a fresh AsyncLocalStorage instance.
    const { requestAuthStorage: freshStorage } = await import("./requestAuth.js");

    const config = {
      headers: new AxiosHeaders({ "x-api-key": "server-default-key" }),
    } as unknown as InternalAxiosRequestConfig;

    await freshStorage.run("caller-key", async () => {
      applyRequestAuth(config);
    });
    expect(config.headers.get("x-api-key")).toBe("caller-key");
  });
});

describe("authorizeInitialize gateway-token path", () => {
  const REENROLL_MESSAGE =
    "Unauthorized: gateway token invalid or expired. Re-enroll at /enroll to get a new one.";

  function issueTestToken(now: number = Date.now()): string {
    process.env.GATEWAY_TOKEN_SECRET = "unit-test-secret";
    const token = issueGatewayToken({
      email: "user@example.com",
      apiKey: "embedded-caller-key",
      now,
    });
    if (!token) {
      throw new Error("expected a token to be issued");
    }
    return token;
  }

  it("allows a valid token in x-api-key with no Basic login and returns effectiveApiKey", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "rejected");

    const result = await authorizeInitialize(
      { clientApiKey: issueTestToken(), authorization: undefined },
      { verifyFn },
    );

    expect(result).toEqual({
      allowed: true,
      email: "user@example.com",
      effectiveApiKey: "embedded-caller-key",
    });
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it("allows a valid token carried as a Bearer value", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "rejected");
    const token = issueTestToken();

    const result = await authorizeInitialize(
      { clientApiKey: undefined, authorization: `Bearer ${token}` },
      { verifyFn },
    );

    expect(result).toEqual({
      allowed: true,
      email: "user@example.com",
      effectiveApiKey: "embedded-caller-key",
    });
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it("refuses an invalid gt1. token with the re-enroll message and never falls through to Basic", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");
    const token = issueTestToken();
    const flipAt = Math.floor(token.length / 2);
    const tampered =
      token.slice(0, flipAt) + (token[flipAt] === "A" ? "B" : "A") + token.slice(flipAt + 1);

    const result = await authorizeInitialize(
      {
        clientApiKey: tampered,
        authorization: basic("user@example.com", "fake-password"),
      },
      { verifyFn },
    );

    expect(result).toEqual({ allowed: false, status: 401, message: REENROLL_MESSAGE });
    expect(verifyFn).not.toHaveBeenCalled();
  });

  it("refuses an expired gt1. token with the re-enroll message", async () => {
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    process.env.MCP_REQUIRE_ACCOUNT_LOGIN = "1";
    process.env.GATEWAY_TOKEN_TTL_DAYS = "1";
    const verifyFn = vi.fn(async (): Promise<AccountLoginVerification> => "verified");
    const expired = issueTestToken(Date.now() - 2 * 86_400_000);

    const result = await authorizeInitialize(
      { clientApiKey: expired, authorization: undefined },
      { verifyFn },
    );

    expect(result).toEqual({ allowed: false, status: 401, message: REENROLL_MESSAGE });
    expect(verifyFn).not.toHaveBeenCalled();
  });
});
