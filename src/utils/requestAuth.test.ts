import { AxiosHeaders, type InternalAxiosRequestConfig } from "axios";
import { describe, expect, it } from "vitest";
import { getRequestApiKey, requestAuthStorage } from "./requestAuth.js";

describe("requestAuthStorage", () => {
  it("has no key outside a request context", () => {
    expect(getRequestApiKey()).toBeUndefined();
  });

  it("returns the key inside the request context", async () => {
    const seen = await requestAuthStorage.run("dokploy-key-placeholder", async () => {
      return getRequestApiKey();
    });
    expect(seen).toBe("dokploy-key-placeholder");
    expect(getRequestApiKey()).toBeUndefined();
  });

  it("treats an empty stored key as no key", async () => {
    const seen = await requestAuthStorage.run("", async () => {
      return getRequestApiKey();
    });
    expect(seen).toBeUndefined();
  });

  it("keeps concurrent contexts isolated", async () => {
    const results = await Promise.all([
      requestAuthStorage.run("key-user-a", async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        return getRequestApiKey();
      }),
      requestAuthStorage.run("key-user-b", async () => {
        await new Promise((resolve) => setTimeout(resolve, 1));
        return getRequestApiKey();
      }),
    ]);
    expect(results).toEqual(["key-user-a", "key-user-b"]);
  });
});

describe("applyRequestAuth", () => {
  it("overrides the x-api-key header with the request key at send time", async () => {
    process.env.DOKPLOY_URL = "https://example.com";
    process.env.DOKPLOY_API_KEY = "server-default-key";
    const { applyRequestAuth } = await import("./apiClient.js");

    const config = {
      headers: new AxiosHeaders({ "x-api-key": "server-default-key" }),
    } as unknown as InternalAxiosRequestConfig;

    await requestAuthStorage.run("caller-key", async () => {
      applyRequestAuth(config);
    });
    expect(config.headers.get("x-api-key")).toBe("caller-key");
  });

  it("leaves the default header untouched when the request carries no key", async () => {
    process.env.DOKPLOY_URL = "https://example.com";
    process.env.DOKPLOY_API_KEY = "server-default-key";
    const { applyRequestAuth } = await import("./apiClient.js");

    const config = {
      headers: new AxiosHeaders({ "x-api-key": "server-default-key" }),
    } as unknown as InternalAxiosRequestConfig;

    applyRequestAuth(config);
    expect(config.headers.get("x-api-key")).toBe("server-default-key");
  });
});
