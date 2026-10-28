import { createHash, createHmac } from "node:crypto";
import type { AccountSession } from "./organization-access.js";
import { z } from "zod";

export interface ClawMuseCloudConfig {
  url: string;
  secret: string;
}

export function clawmuseCloudConfig(env = process.env): ClawMuseCloudConfig | undefined {
  const url = env["CLAWMUSE_CLOUD_SERVICE_URL"];
  const secret = env["CLAWMUSE_CLOUD_SERVICE_SECRET"];
  if (!url && !secret) return undefined;
  if (!url || !secret || secret.length < 32)
    throw new Error("Invalid ClawMuse cloud configuration");
  const endpoint = new URL(url);
  if (
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    endpoint.pathname !== "/" ||
    (endpoint.protocol !== "https:" &&
      !(
        endpoint.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname)
      ))
  )
    throw new Error("Invalid ClawMuse cloud service URL");
  return { url: endpoint.origin, secret };
}

/** User identity always comes from the bearer session. The browser never selects an owner. */
export class ClawMuseCloud {
  constructor(
    private readonly config: ClawMuseCloudConfig | undefined,
    private readonly readSession: (headers: Headers) => Promise<AccountSession | undefined>,
  ) {}

  get enabled(): boolean {
    return this.config !== undefined;
  }

  private async call(
    userId: string,
    operation: "" | "/start" | "/pause" | "/delete",
  ): Promise<Response> {
    if (!this.config) throw new Error("cloud_unavailable");
    const owner = createHash("sha256").update(`clawmuse-cloud-user\0${userId}`).digest("hex");
    const path = `/internal/space${operation}`;
    const method = operation ? "POST" : "GET";
    const timestamp = String(Date.now());
    const signature = createHmac("sha256", this.config.secret)
      .update([method, path, owner, timestamp, ""].join("\n"))
      .digest("hex");
    return fetch(this.config.url + path, {
      method,
      redirect: "error",
      signal: AbortSignal.timeout(operation === "/delete" ? 75000 : 15000),
      headers: {
        "x-clawmuse-owner": owner,
        "x-clawmuse-timestamp": timestamp,
        "x-clawmuse-signature": signature,
      },
    });
  }

  async deleteAccount(userId: string): Promise<void> {
    if (!this.enabled) return;
    const response = await this.call(userId, "/delete");
    const result = z.object({ deleted: z.literal(true) }).safeParse(await response.json());
    if (!response.ok || !result.success) throw new Error("cloud_deletion_failed");
  }

  async handle(request: Request): Promise<Response> {
    if (!this.enabled) return Response.json({ error: "cloud_unavailable" }, { status: 503 });
    if (!request.headers.get("authorization")?.startsWith("Bearer "))
      return Response.json({ error: "unauthorized" }, { status: 401 });
    const headers = new Headers(request.headers);
    headers.delete("cookie");
    const session = await this.readSession(headers);
    if (!session) return Response.json({ error: "unauthorized" }, { status: 401 });
    if (session.mustChangePassword)
      return Response.json({ error: "password_change_required" }, { status: 403 });
    const path = new URL(request.url).pathname;
    const operations = new Map<string, "" | "/start" | "/pause">([
      ["/api/auth/clawmuse/cloud", ""],
      ["/api/auth/clawmuse/cloud/start", "/start"],
      ["/api/auth/clawmuse/cloud/pause", "/pause"],
    ]);
    const operation = operations.get(path);
    if (operation === undefined) return Response.json({ error: "not_found" }, { status: 404 });
    if (request.method !== (operation ? "POST" : "GET"))
      return Response.json({ error: "method_not_allowed" }, { status: 405 });
    try {
      const response = await this.call(session.userId, operation);
      const text = await response.text();
      if (text.length > 65536) throw new Error("cloud_response_too_large");
      const result: unknown = JSON.parse(text);
      if (!response.ok) {
        const parsed = z.object({ error: z.object({ type: z.string() }) }).safeParse(result);
        const code = parsed.success ? parsed.data.error.type : undefined;
        if (code === "insufficient_credit" || code === "cloud_capacity_reached")
          return Response.json(
            { error: code },
            { status: response.status, headers: { "cache-control": "no-store" } },
          );
        throw new Error("cloud_request_failed");
      }
      return Response.json(result, { headers: { "cache-control": "no-store" } });
    } catch {
      return Response.json(
        { error: "cloud_unavailable" },
        { status: 503, headers: { "cache-control": "no-store" } },
      );
    }
  }
}
