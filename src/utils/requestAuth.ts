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

/**
 * Extract the caller's Dokploy API key from request headers. The key lives
 * in the "x-api-key" header. "Authorization" is accepted only when it uses
 * the Bearer scheme: gateways in front of this server may add their own
 * Authorization header (for example HTTP Basic auth carrying the caller's
 * Dokploy account login), and such a value must never be mistaken for a
 * Dokploy key.
 */
export function extractClientApiKey(
  header: (name: string) => string | undefined,
): string | undefined {
  const headerKey = header("x-api-key");
  if (headerKey) {
    return headerKey;
  }
  const authorization = header("authorization");
  if (authorization?.startsWith("Bearer ")) {
    const token = authorization.slice("Bearer ".length).trim();
    return token.length > 0 ? token : undefined;
  }
  return undefined;
}
