import { afterEach, describe, expect, it, vi } from "vitest";

const ENV_KEYS = ["DOKPLOY_URL", "DOKPLOY_API_KEY", "MCP_REQUIRE_CLIENT_KEY"] as const;
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

describe("getClientConfig in per-user passthrough mode", () => {
  it("does not require DOKPLOY_API_KEY when MCP_REQUIRE_CLIENT_KEY=1", async () => {
    process.env.DOKPLOY_URL = "https://example.com";
    delete process.env.DOKPLOY_API_KEY;
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    vi.resetModules();

    const { getClientConfig } = await import("./clientConfig.js");
    const config = getClientConfig();

    expect(config.authToken).toBe("");
    expect(config.dokployUrl).toBe("https://example.com");
  });

  it("still requires DOKPLOY_API_KEY without the passthrough flag", async () => {
    process.env.DOKPLOY_URL = "https://example.com";
    delete process.env.DOKPLOY_API_KEY;
    delete process.env.MCP_REQUIRE_CLIENT_KEY;
    vi.resetModules();

    const { getClientConfig } = await import("./clientConfig.js");
    expect(() => getClientConfig()).toThrow(/DOKPLOY_API_KEY is not defined/);
  });

  it("keeps a configured DOKPLOY_API_KEY as the default token when the flag is set", async () => {
    process.env.DOKPLOY_URL = "https://example.com";
    process.env.DOKPLOY_API_KEY = "configured-default-key";
    process.env.MCP_REQUIRE_CLIENT_KEY = "1";
    vi.resetModules();

    const { getClientConfig } = await import("./clientConfig.js");
    expect(getClientConfig().authToken).toBe("configured-default-key");
  });
});
