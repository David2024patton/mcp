import { AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type AccountLoginVerification,
  authorizeInitialize,
  parseBasicAuthCredentials,
  verifyDokployAccountLogin,
} from "./accountAuth.js";
import { extractClientApiKey } from "./requestAuth.js";

const ENV_KEYS = [
  "DOKPLOY_URL",
  "DOKPLOY_API_KEY",
  "MCP_REQUIRE_CLIENT_KEY",
  "MCP_REQUIRE_ACCOUNT_LOGIN",
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
