import { createHash, createHmac } from "node:crypto";
import type { AccountSession } from "./organization-access.js";
import { z } from "zod";
import { reportFailure } from "../failures/index.js";

export interface ClawMuseCloudConfig {
  url: string;
  secret: string;
  access: {
    mode: "off" | "allowlist" | "all";
    userIds: string[];
  };
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
  const mode = z.enum(["off", "allowlist", "all"]).parse(env["CLAWMUSE_CLOUD_ACCESS"] || "off");
  const userIds = z
    .array(z.string().regex(/^[A-Za-z0-9_-]{1,128}$/))
    .max(100)
    .parse([
      ...new Set(
        (env["CLAWMUSE_CLOUD_ALLOWED_USER_IDS"] ?? "")
          .split(",")
          .map((id) => id.trim())
          .filter(Boolean),
      ),
    ]);
  return { url: endpoint.origin, secret, access: { mode, userIds } };
}

/** User identity always comes from the bearer session. The browser never selects an owner. */
export class ClawMuseCloud {
  private policyTimer: ReturnType<typeof setInterval> | undefined;
  private policySync: Promise<void> | undefined;
  private policySyncedAt = 0;

  constructor(
    private readonly config: ClawMuseCloudConfig | undefined,
    private readonly readSession: (headers: Headers) => Promise<AccountSession | undefined>,
  ) {}

  get enabled(): boolean {
    return this.config !== undefined;
  }

  allows(userId: string): boolean {
    const access = this.config?.access;
    return (
      access?.mode === "all" || (access?.mode === "allowlist" && access.userIds.includes(userId))
    );
  }

  async enabledFor(userId: string): Promise<boolean> {
    if (!this.allows(userId)) return false;
    try {
      await this.syncPolicy();
      return true;
    } catch {
      return false;
    }
  }

  start(): void {
    if (!this.config || this.policyTimer) return;
    const refresh = () => {
      void this.syncPolicy().catch(() => {
        reportFailure(new Error("cloud_policy_sync_failed"), {
          operation: "clawmuse.cloud.policy.sync",
          component: "auth",
        });
      });
    };
    refresh();
    this.policyTimer = setInterval(refresh, 30000);
    this.policyTimer.unref();
  }

  async close(): Promise<void> {
    clearInterval(this.policyTimer);
    await this.policySync?.catch(() => undefined);
  }

  private syncPolicy(): Promise<void> {
    if (this.policySync) return this.policySync;
    if (!this.config || Date.now() - this.policySyncedAt < 20000) return Promise.resolve();
    const raw = JSON.stringify({
      mode: this.config.access.mode,
      owners: this.config.access.userIds.map((id) =>
        createHash("sha256").update(`clawmuse-cloud-user\0${id}`).digest("hex"),
      ),
      expiresAt: Date.now() + 120000,
    });
    this.policySync = this.signedCall("0".repeat(64), "/internal/access-policy", "POST", raw)
      .then(async (response) => {
        const result = z.object({ synced: z.literal(true) }).safeParse(await response.json());
        if (!response.ok || !result.success) throw new Error("cloud_policy_sync_failed");
        this.policySyncedAt = Date.now();
        return;
      })
      .finally(() => {
        this.policySync = undefined;
      });
    return this.policySync;
  }

  private signedCall(owner: string, path: string, method: string, raw = ""): Promise<Response> {
    if (!this.config) throw new Error("cloud_unavailable");
    const timestamp = String(Date.now());
    const signature = createHmac("sha256", this.config.secret)
      .update([method, path, owner, timestamp, raw].join("\n"))
      .digest("hex");
    return fetch(this.config.url + path, {
      method,
      ...(raw ? { body: raw } : {}),
      redirect: "error",
      signal: AbortSignal.timeout(path.endsWith("/delete") ? 75000 : 15000),
      headers: {
        "content-type": "application/json",
        "x-clawmuse-owner": owner,
        "x-clawmuse-timestamp": timestamp,
        "x-clawmuse-signature": signature,
      },
    });
  }

  private async call(
    userId: string,
    operation: "" | "/start" | "/pause" | "/delete",
  ): Promise<Response> {
    if (!this.config) throw new Error("cloud_unavailable");
    const owner = createHash("sha256").update(`clawmuse-cloud-user\0${userId}`).digest("hex");
    const path = `/internal/space${operation}`;
    const method = operation ? "POST" : "GET";
    return this.signedCall(owner, path, method);
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
    if (!this.allows(session.userId))
      return Response.json(
        { error: "cloud_not_enabled" },
        { status: 403, headers: { "cache-control": "no-store" } },
      );
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
      await this.syncPolicy();
      const response = await this.call(session.userId, operation);
      const text = await response.text();
      if (text.length > 65536) throw new Error("cloud_response_too_large");
      const result: unknown = JSON.parse(text);
      if (!response.ok) {
        const parsed = z.object({ error: z.object({ type: z.string() }) }).safeParse(result);
        const code = parsed.success ? parsed.data.error.type : undefined;
        if (
          code === "insufficient_credit" ||
          code === "cloud_capacity_reached" ||
          code === "cloud_not_enabled"
        )
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
