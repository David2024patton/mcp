import { describe, expect, it, vi } from "vitest";

// Mock apiClient before linkDomain.ts is imported — the real module calls
// getClientConfig() at module level, which requires Dokploy env vars.
// These tests always inject their own deps, so the client is never used.
vi.mock("../utils/apiClient.js", () => ({
  default: { get: vi.fn(), post: vi.fn() },
  setAuthToken: vi.fn(),
  clearAuthToken: vi.fn(),
}));

import {
  deriveRecordName,
  executeLinkDomain,
  type LinkDomainDeps,
  type LinkDomainInput,
} from "./linkDomain.js";

const BASE_INPUT: LinkDomainInput = {
  applicationId: "app-123",
  host: "app.example.com",
  zone: "example.com",
  provider: "cloudflare",
  credentials: { apiToken: "fake-provider-token" },
};

const FRONT_DOOR = "107.90.116.157";

function makeDeps(overrides: Partial<LinkDomainDeps> = {}): LinkDomainDeps {
  return {
    env: {
      DNS_LINK_URL: "http://dns-link:8080",
      DNS_LINK_TOKEN: "shared-token",
      FRONT_DOOR_IP: FRONT_DOOR,
    },
    fetchFn: vi.fn(
      async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
    ) as unknown as typeof fetch,
    listDomains: vi.fn(async () => []),
    createDomain: vi.fn(async () => ({ domainId: "dom-new" })),
    resolveA: vi.fn(async () => [FRONT_DOOR]),
    sleep: vi.fn(async () => {}),
    pollIntervalMs: 1,
    pollTimeoutMs: 10,
    ...overrides,
  };
}

function resultData(result: { content: { text: string }[] }) {
  return JSON.parse(result.content[0].text) as {
    success: boolean;
    error?: string;
    data?: Record<string, unknown>;
  };
}

describe("deriveRecordName", () => {
  it("maps the apex host to @", () => {
    expect(deriveRecordName("example.com", "example.com")).toBe("@");
  });

  it("extracts the prefix for a subdomain", () => {
    expect(deriveRecordName("app.example.com", "example.com")).toBe("app");
  });

  it("extracts a nested prefix", () => {
    expect(deriveRecordName("a.b.example.com", "example.com")).toBe("a.b");
  });

  it("is case-insensitive and ignores trailing dots", () => {
    expect(deriveRecordName("App.Example.COM.", "EXAMPLE.com.")).toBe("app");
  });

  it("rejects a host outside the zone", () => {
    expect(() => deriveRecordName("app.other.com", "example.com")).toThrow(/not inside zone/);
  });

  it("rejects a host that merely ends with the zone string", () => {
    expect(() => deriveRecordName("badexample.com", "example.com")).toThrow(/not inside zone/);
  });
});

describe("executeLinkDomain", () => {
  it("fails fast with a clear error when the DNS link service is not configured", async () => {
    const deps = makeDeps({ env: { FRONT_DOOR_IP: FRONT_DOOR } });
    const result = await executeLinkDomain(BASE_INPUT, deps);
    expect(result.isError).toBe(true);
    expect(resultData(result).error).toBe("DNS link service is not configured on this gateway");
    expect(deps.fetchFn).not.toHaveBeenCalled();
    expect(deps.listDomains).not.toHaveBeenCalled();
    expect(deps.createDomain).not.toHaveBeenCalled();
  });

  it("fails fast when only the token is missing", async () => {
    const deps = makeDeps({
      env: { DNS_LINK_URL: "http://dns-link:8080" },
    });
    const result = await executeLinkDomain(BASE_INPUT, deps);
    expect(result.isError).toBe(true);
    expect(resultData(result).error).toContain("not configured");
    expect(deps.fetchFn).not.toHaveBeenCalled();
  });

  it("stops at the DNS step on failure and never calls Dokploy (ordering proof)", async () => {
    const deps = makeDeps({
      fetchFn: vi.fn(
        async () =>
          new Response(JSON.stringify({ error: "cloudflare auth failed" }), {
            status: 502,
          }),
      ) as unknown as typeof fetch,
    });
    const result = await executeLinkDomain(BASE_INPUT, deps);
    expect(result.isError).toBe(true);
    const parsed = resultData(result);
    expect(parsed.error).toContain("DNS record write failed");
    expect(JSON.stringify(parsed)).toContain("cloudflare auth failed");
    expect(deps.listDomains).not.toHaveBeenCalled();
    expect(deps.createDomain).not.toHaveBeenCalled();
    expect(deps.resolveA).not.toHaveBeenCalled();
  });

  it("sends the DNS write with the shared token header and derived record", async () => {
    const deps = makeDeps();
    const result = await executeLinkDomain(BASE_INPUT, deps);
    expect(result.isError).toBeUndefined();
    const fetchMock = deps.fetchFn as unknown as ReturnType<typeof vi.fn>;
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [
      string,
      { headers: Record<string, string>; body: string },
    ];
    expect(url).toBe("http://dns-link:8080/v1/records/set");
    expect(init.headers["X-DNS-Link-Token"]).toBe("shared-token");
    const body = JSON.parse(init.body) as Record<string, unknown>;
    expect(body).toMatchObject({
      provider: "cloudflare",
      zone: "example.com",
      type: "A",
      name: "app",
      value: FRONT_DOOR,
      credentials: { apiToken: "fake-provider-token" },
    });
  });

  it("creates the Dokploy domain and reports resolved=true on the happy path", async () => {
    const deps = makeDeps();
    const result = await executeLinkDomain(BASE_INPUT, deps);
    const parsed = resultData(result);
    expect(parsed.success).toBe(true);
    expect(deps.createDomain).toHaveBeenCalledWith({
      applicationId: "app-123",
      host: "app.example.com",
      path: "/",
      port: 3000,
      https: true,
      certificateType: "letsencrypt",
    });
    expect(parsed.data).toMatchObject({
      dnsRecordWritten: true,
      domainId: "dom-new",
      domainCreated: true,
      resolved: true,
      recordName: "app",
      recordValue: FRONT_DOOR,
    });
  });

  it("treats an existing domain with the same host as success (idempotent)", async () => {
    const deps = makeDeps({
      listDomains: vi.fn(async () => [{ domainId: "dom-existing", host: "app.example.com" }]),
    });
    const result = await executeLinkDomain(BASE_INPUT, deps);
    const parsed = resultData(result);
    expect(parsed.success).toBe(true);
    expect(deps.createDomain).not.toHaveBeenCalled();
    expect(parsed.data).toMatchObject({
      domainId: "dom-existing",
      domainCreated: false,
    });
  });

  it("reports resolved=false (not an error) when propagation is still pending", async () => {
    const deps = makeDeps({
      resolveA: vi.fn(async () => {
        throw new Error("NXDOMAIN");
      }),
    });
    const result = await executeLinkDomain(BASE_INPUT, deps);
    const parsed = resultData(result);
    expect(result.isError).toBeUndefined();
    expect(parsed.success).toBe(true);
    expect(parsed.data).toMatchObject({ resolved: false });
  });

  it("honors an explicit port and the apex record name", async () => {
    const deps = makeDeps();
    const result = await executeLinkDomain(
      { ...BASE_INPUT, host: "example.com", port: 8080 },
      deps,
    );
    expect(resultData(result).success).toBe(true);
    expect(deps.createDomain).toHaveBeenCalledWith(
      expect.objectContaining({ port: 8080, host: "example.com" }),
    );
    const fetchMock = deps.fetchFn as unknown as ReturnType<typeof vi.fn>;
    const body = JSON.parse((fetchMock.mock.calls[0][1] as { body: string }).body) as Record<
      string,
      unknown
    >;
    expect(body.name).toBe("@");
  });

  it("rejects a host outside the zone before any network call", async () => {
    const deps = makeDeps();
    const result = await executeLinkDomain({ ...BASE_INPUT, host: "app.other.com" }, deps);
    expect(result.isError).toBe(true);
    expect(deps.fetchFn).not.toHaveBeenCalled();
    expect(deps.createDomain).not.toHaveBeenCalled();
  });
});
