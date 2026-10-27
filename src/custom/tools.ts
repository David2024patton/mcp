import type { ZodObject, ZodRawShape } from "zod";
import type { ToolAnnotations } from "../types.js";
import type { FormattedResponse } from "../utils/responseFormatter.js";
import { linkDomainHandler, linkDomainInputSchema } from "./linkDomain.js";

/**
 * Hand-written tools registered alongside the generated Dokploy API tools.
 *
 * src/generated/tools.ts is produced by `pnpm generate` from the Dokploy
 * OpenAPI spec, so custom tools must NOT be added there (a regeneration
 * would silently drop them). Custom tools live in this module instead and
 * are registered by src/server.ts next to the generated ones.
 */
export interface CustomToolDefinition {
  name: string;
  description: string;
  /** Preset/tag group this tool belongs to, same semantics as generated tools. */
  tag: string;
  schema: ZodObject<ZodRawShape>;
  annotations?: ToolAnnotations;
  handler: (input: Record<string, unknown>) => Promise<FormattedResponse>;
}

export const customTools: CustomToolDefinition[] = [
  {
    name: "link-domain",
    tag: "domain",
    description:
      "Link your own domain to one of your applications in a single call: " +
      "writes the DNS A record at your DNS provider (via the dns-link " +
      "service, using the provider credentials you pass for this call only; " +
      "they are never stored), then attaches the domain in Dokploy with " +
      "HTTPS (Let's Encrypt), then checks whether the name already resolves " +
      "to the server. Inputs: applicationId, host (full hostname), zone " +
      "(the DNS zone the host belongs to), provider (cloudflare, route53, " +
      "godaddy, namecheap, porkbun, hetzner, digitalocean, ovh, gandi, " +
      "linode, dnsimple), credentials (that provider's API fields), " +
      "port (optional, default 3000).",
    schema: linkDomainInputSchema as ZodObject<ZodRawShape>,
    annotations: {
      title: "Link Domain",
      idempotentHint: true,
      openWorldHint: true,
    },
    handler: async (input) => linkDomainHandler(input as Parameters<typeof linkDomainHandler>[0]),
  },
];
