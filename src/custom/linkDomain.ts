import { Resolver } from "node:dns/promises";
import { z } from "zod";
import apiClient from "../utils/apiClient.js";
import { createLogger } from "../utils/logger.js";
import { type FormattedResponse, ResponseFormatter } from "../utils/responseFormatter.js";

const logger = createLogger("LinkDomain");

/**
 * link-domain: attach a tenant's own domain to one of their applications in
 * a single call.
 *
 * The flow is deliberately ordered:
 *   1. Write the DNS A record at the tenant's DNS provider through the
 *      dns-link service (the tenant's provider credentials travel per call
 *      and are never stored on this gateway).
 *   2. Only after the record is written, create the domain in Dokploy
 *      through the shared API client, so the call goes out with the
 *      caller's own Dokploy API key and inherits exactly their scope.
 *   3. Poll public DNS until the host resolves to the front door (or the
 *      poll window ends; pending propagation is reported, not an error).
 *
 * If the DNS step fails, Dokploy is never called: a domain attached in
 * Dokploy with no DNS record behind it would only half-work and would be
 * hard to diagnose from the tenant's side.
 */

export const linkDomainInputSchema = z.object({
  applicationId: z.string().min(1),
  host: z.string().min(1),
  zone: z.string().min(1),
  provider: z.string().min(1),
  credentials: z.record(z.string(), z.unknown()),
  port: z.number().int().gte(1).lte(65535).optional(),
});

export type LinkDomainInput = z.infer<typeof linkDomainInputSchema>;

export interface DokployDomain {
  domainId?: string;
  host?: string;
  [key: string]: unknown;
}

export interface LinkDomainDeps {
  env: Record<string, string | undefined>;
  fetchFn: typeof fetch;
  listDomains: (applicationId: string) => Promise<DokployDomain[]>;
  createDomain: (body: Record<string, unknown>) => Promise<DokployDomain>;
  resolveA: (host: string) => Promise<string[]>;
  sleep: (ms: number) => Promise<void>;
  pollIntervalMs: number;
  pollTimeoutMs: number;
}

const DEFAULT_FRONT_DOOR_IP = "107.90.116.157";
const DEFAULT_POLL_INTERVAL_MS = 5_000;
const DEFAULT_POLL_TIMEOUT_MS = 90_000;

function normalizeName(value: string): string {
  return value.trim().toLowerCase().replace(/\.+$/, "");
}

/**
 * Derives the DNS record name for `host` inside `zone`:
 * the apex itself is "@", a subdomain yields its prefix, and a host outside
 * the zone is an error (writing it would target the wrong zone entirely).
 */
export function deriveRecordName(host: string, zone: string): string {
  const h = normalizeName(host);
  const z = normalizeName(zone);
  if (h === z) return "@";
  const suffix = `.${z}`;
  if (h.endsWith(suffix)) {
    const prefix = h.slice(0, h.length - suffix.length);
    if (prefix.length > 0) return prefix;
  }
  throw new Error(`Host "${host}" is not inside zone "${zone}"`);
}

async function readErrorDetail(response: Response): Promise<string> {
  try {
    const text = await response.text();
    if (!text) return response.statusText;
    try {
      const parsed = JSON.parse(text) as { error?: string; message?: string };
      return parsed.error ?? parsed.message ?? text;
    } catch {
      return text;
    }
  } catch {
    return response.statusText;
  }
}

export async function executeLinkDomain(
  input: LinkDomainInput,
  deps: LinkDomainDeps,
): Promise<FormattedResponse> {
  const dnsLinkUrl = deps.env.DNS_LINK_URL?.replace(/\/+$/, "");
  const dnsLinkToken = deps.env.DNS_LINK_TOKEN;
  if (!dnsLinkUrl || !dnsLinkToken) {
    return ResponseFormatter.error(
      "DNS link service is not configured on this gateway",
      "Set DNS_LINK_URL and DNS_LINK_TOKEN on the gateway application and redeploy.",
    );
  }

  const host = normalizeName(input.host);
  const zone = normalizeName(input.zone);
  const port = input.port ?? 3000;
  const frontDoorIp = deps.env.FRONT_DOOR_IP || DEFAULT_FRONT_DOOR_IP;

  let recordName: string;
  try {
    recordName = deriveRecordName(host, zone);
  } catch (error) {
    return ResponseFormatter.error(
      "Host is not inside the given zone",
      error instanceof Error ? error.message : "Unknown error",
    );
  }

  // Step 1: write the DNS A record. Any failure stops the flow here;
  // Dokploy is not called with a domain that has no DNS behind it.
  let dnsResponse: Response;
  try {
    dnsResponse = await deps.fetchFn(`${dnsLinkUrl}/v1/records/set`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-DNS-Link-Token": dnsLinkToken,
      },
      body: JSON.stringify({
        provider: input.provider,
        zone,
        type: "A",
        name: recordName,
        value: frontDoorIp,
        credentials: input.credentials,
      }),
    });
  } catch (error) {
    return ResponseFormatter.error(
      "DNS link service unreachable",
      error instanceof Error ? error.message : "Unknown error",
    );
  }
  if (!dnsResponse.ok) {
    const detail = await readErrorDetail(dnsResponse);
    logger.warn("DNS record write failed", {
      provider: input.provider,
      zone,
      status: dnsResponse.status,
    });
    return ResponseFormatter.error(`DNS record write failed (${dnsResponse.status})`, detail);
  }

  // Step 2: attach the domain in Dokploy with the caller's own key (the
  // shared API client applies it per request). Idempotent: an existing
  // domain with the same host counts as success.
  let domainId: string | undefined;
  let domainCreated = false;
  try {
    const existing = await deps.listDomains(input.applicationId);
    const found = existing.find((d) => d.host && normalizeName(d.host) === host);
    if (found) {
      domainId = found.domainId;
    } else {
      const created = await deps.createDomain({
        applicationId: input.applicationId,
        host,
        path: "/",
        port,
        https: true,
        certificateType: "letsencrypt",
      });
      domainId = created.domainId;
      domainCreated = true;
    }
  } catch (error) {
    return ResponseFormatter.error(
      "DNS record written, but attaching the domain in Dokploy failed",
      error instanceof Error ? error.message : "Unknown error",
    );
  }

  // Step 3: poll public DNS until the host resolves to the front door.
  // Pending propagation is reported in the result, never as an error.
  let resolved = false;
  const deadline = Date.now() + deps.pollTimeoutMs;
  for (;;) {
    try {
      const addresses = await deps.resolveA(host);
      if (addresses.includes(frontDoorIp)) {
        resolved = true;
        break;
      }
    } catch {
      // Not propagated yet (NXDOMAIN / no answer): keep polling.
    }
    if (Date.now() + deps.pollIntervalMs > deadline) break;
    await deps.sleep(deps.pollIntervalMs);
  }

  return ResponseFormatter.success("link-domain completed", {
    host,
    zone,
    provider: input.provider,
    recordName,
    recordType: "A",
    recordValue: frontDoorIp,
    dnsRecordWritten: true,
    domainId,
    domainCreated,
    resolved,
  });
}

function defaultDeps(): LinkDomainDeps {
  const resolver = new Resolver();
  resolver.setServers(["1.1.1.1"]);
  return {
    env: process.env,
    fetchFn: fetch,
    listDomains: async (applicationId) => {
      const response = await apiClient.get("/domain.byApplicationId", {
        params: { applicationId },
      });
      return (response.data ?? []) as DokployDomain[];
    },
    createDomain: async (body) => {
      const response = await apiClient.post("/domain.create", body);
      return (response.data ?? {}) as DokployDomain;
    },
    resolveA: (host) => resolver.resolve4(host),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    pollIntervalMs: DEFAULT_POLL_INTERVAL_MS,
    pollTimeoutMs: DEFAULT_POLL_TIMEOUT_MS,
  };
}

export async function linkDomainHandler(input: LinkDomainInput): Promise<FormattedResponse> {
  return executeLinkDomain(input, defaultDeps());
}
