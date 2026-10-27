#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import type { HttpBindings } from "@hono/node-server";
import { serve } from "@hono/node-server";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { Hono } from "hono";
import { createServer } from "./server.js";
import { createLogger } from "./utils/logger.js";
import { requestAuthStorage } from "./utils/requestAuth.js";

const PORT = 3000;
const logger = createLogger("MCP-HTTP-Server");

// Per-user passthrough mode: when MCP_REQUIRE_CLIENT_KEY=1, every session
// must be opened with the caller's own Dokploy API key, and that key is
// forwarded to Dokploy for the session's tool calls. The server holds no
// key of its own; identity comes from the key the client presents.
const requireClientKey = process.env.MCP_REQUIRE_CLIENT_KEY === "1";

// Extract the caller's Dokploy API key from request headers. The key lives
// in the "x-api-key" header. "Authorization" is accepted only when it uses
// the Bearer scheme: gateways in front of this server may add their own
// Authorization header (for example HTTP Basic auth as a door check), and
// such a value must never be mistaken for a Dokploy key.
function extractClientApiKey(header: (name: string) => string | undefined): string | undefined {
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

const jsonrpcError = (code: number, message: string) => ({
  jsonrpc: "2.0" as const,
  error: { code, message },
  id: null,
});

// When MCP transport takes over the raw Node response, we must prevent
// Hono/@hono/node-server from trying to write its own response headers.
// We return a Promise that NEVER resolves — the underlying Node response
// is already being handled by the MCP transport, so Hono must not touch it.
function neverResolve(): Promise<never> {
  return new Promise(() => {});
}

export async function main() {
  const app = new Hono<{ Bindings: HttpBindings }>();

  const transports = {
    streamable: {} as Record<string, StreamableHTTPServerTransport>,
    sse: {} as Record<string, SSEServerTransport>,
  };

  // Health check
  app.get("/health", (c) => c.json({ status: "ok", timestamp: new Date().toISOString() }));

  // Modern Streamable HTTP - POST
  app.post("/mcp", async (c) => {
    const { incoming, outgoing } = c.env;
    try {
      const sessionId = c.req.header("mcp-session-id");
      const clientApiKey = extractClientApiKey((name) => c.req.header(name));
      let transport: StreamableHTTPServerTransport;
      const body = await c.req.json();

      if (sessionId && transports.streamable[sessionId]) {
        transport = transports.streamable[sessionId];
      } else if (!sessionId && isInitializeRequest(body)) {
        if (requireClientKey && !clientApiKey) {
          return c.json(
            jsonrpcError(
              -32001,
              "Unauthorized: this gateway requires your own Dokploy API key. Send it in the 'x-api-key' header (or as 'Authorization: Bearer <key>').",
            ),
            401,
          );
        }
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sid) => {
            transports.streamable[sid] = transport;
            logger.info("New MCP session initialized", { sessionId: sid });
          },
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            logger.info("MCP session closed", { sessionId: transport.sessionId });
            delete transports.streamable[transport.sessionId];
          }
        };

        const server = createServer();
        await server.connect(
          transport as unknown as import("@modelcontextprotocol/sdk/shared/transport.js").Transport,
        );
      } else {
        return c.json(
          jsonrpcError(
            -32000,
            "Bad Request: No valid session ID or invalid initialization request",
          ),
          400,
        );
      }

      // Tool calls dispatched from here run inside the request's async
      // context, so the API client sends the caller's key (when presented)
      // rather than the server default.
      await requestAuthStorage.run(clientApiKey ?? "", async () => {
        await transport.handleRequest(incoming, outgoing, body);
      });
      return neverResolve();
    } catch (error) {
      logger.error("Error handling HTTP request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Modern Streamable HTTP - GET (SSE notifications)
  app.get("/mcp", async (c) => {
    const { incoming, outgoing } = c.env;
    const sessionId = c.req.header("mcp-session-id");

    if (!sessionId || !transports.streamable[sessionId]) {
      return c.json(jsonrpcError(-32000, "Invalid or missing session ID"), 400);
    }

    const clientApiKey = extractClientApiKey((name) => c.req.header(name));
    try {
      const transport = transports.streamable[sessionId];
      await requestAuthStorage.run(clientApiKey ?? "", async () => {
        await transport.handleRequest(incoming, outgoing);
      });
      return neverResolve();
    } catch (error) {
      logger.error("Error handling GET request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Modern Streamable HTTP - DELETE (session termination)
  app.delete("/mcp", async (c) => {
    const { incoming, outgoing } = c.env;
    const sessionId = c.req.header("mcp-session-id");

    if (!sessionId || !transports.streamable[sessionId]) {
      return c.json(jsonrpcError(-32000, "Invalid or missing session ID"), 400);
    }

    const clientApiKey = extractClientApiKey((name) => c.req.header(name));
    try {
      const transport = transports.streamable[sessionId];
      await requestAuthStorage.run(clientApiKey ?? "", async () => {
        await transport.handleRequest(incoming, outgoing);
      });

      if (transports.streamable[sessionId]) {
        logger.info("MCP session terminated", { sessionId });
        delete transports.streamable[sessionId];
      }
      return neverResolve();
    } catch (error) {
      logger.error("Error handling DELETE request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Legacy SSE endpoint
  app.get("/sse", async (c) => {
    const { outgoing } = c.env;
    try {
      const transport = new SSEServerTransport("/messages", outgoing);
      transports.sse[transport.sessionId] = transport;

      outgoing.on("close", () => {
        logger.info("Legacy SSE session closed", { sessionId: transport.sessionId });
        delete transports.sse[transport.sessionId];
      });

      const server = createServer();
      await server.connect(transport);
      logger.info("New legacy SSE session initialized", { sessionId: transport.sessionId });
      return neverResolve();
    } catch (error) {
      logger.error("Error handling SSE request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  // Legacy message endpoint
  app.post("/messages", async (c) => {
    const { incoming, outgoing } = c.env;
    try {
      const sessionId = c.req.query("sessionId");
      if (!sessionId) {
        return c.json(jsonrpcError(-32000, "sessionId query parameter is required"), 400);
      }

      const transport = transports.sse[sessionId];
      if (!transport) {
        return c.json(jsonrpcError(-32000, "No transport found for sessionId"), 400);
      }

      const body = await c.req.json();
      await transport.handlePostMessage(incoming, outgoing, body);
      return neverResolve();
    } catch (error) {
      logger.error("Error handling legacy message request", {
        error: error instanceof Error ? error.message : String(error),
      });
      return c.json(jsonrpcError(-32603, "Internal server error"), 500);
    }
  });

  serve({ fetch: app.fetch, port: PORT }, () => {
    logger.info("MCP Dokploy server started", {
      port: PORT,
      protocols: ["Streamable HTTP (MCP 2025-03-26)", "Legacy SSE (MCP 2024-11-05)"],
      endpoints: {
        modern: `http://localhost:${PORT}/mcp`,
        legacy: `http://localhost:${PORT}/sse`,
        health: `http://localhost:${PORT}/health`,
      },
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    logger.error("Fatal error occurred", {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    process.exit(1);
  });
}
