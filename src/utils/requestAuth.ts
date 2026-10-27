import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Per-request Dokploy API key storage.
 *
 * In HTTP mode, each incoming request may carry the caller's own Dokploy
 * API key (header "x-api-key" or "Authorization: Bearer <key>"). The HTTP
 * server stores that key here for the duration of the request so the API
 * client can send it to Dokploy instead of the server-wide default token.
 *
 * This lets a hosted MCP gateway act strictly with the caller's own scope:
 * identity comes from the key the client presents, so no user's key needs
 * to be stored on the server.
 */
export const requestAuthStorage = new AsyncLocalStorage<string>();

/**
 * Returns the Dokploy API key presented with the current request, or
 * undefined when the current execution is not tied to a request or the
 * request carried no key.
 */
export function getRequestApiKey(): string | undefined {
  const key = requestAuthStorage.getStore();
  return key && key.length > 0 ? key : undefined;
}
