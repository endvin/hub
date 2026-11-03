import { z } from "zod";
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { WebSocket, WebSocketServer } from "ws";
import type { DatabaseRuntime } from "../db/runtime/index.js";
import type { AccountSession } from "./organization-access.js";

const prefix = "/api/auth/clawmuse/official";
interface Ticket {
  bearer: string;
  expires: number;
}

export class ClawMuseOfficial {
  private key: Buffer;
  private sockets = new Set<WebSocket>();
  private wss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 * 1024 });
  constructor(
    secret: string,
    private database: DatabaseRuntime,
    private readSession: (headers: Headers) => Promise<AccountSession | undefined>,
    private origin: string,
    private env = process.env,
  ) {
    this.key = createHash("sha256")
      .update("clawmuse-official-session-v1\0" + secret)
      .digest();
  }

  private seal(bearer: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const body = cipher.update(JSON.stringify({ bearer, expires: Date.now() + 60 * 60 * 1000 }));
    return Buffer.concat([iv, body, cipher.final(), cipher.getAuthTag()]).toString("base64url");
  }
  private open(token: string): Ticket {
    if (token.length > 8192) throw new Error("invalid_ticket");
    const raw = Buffer.from(token, "base64url");
    const cipher = createDecipheriv("aes-256-gcm", this.key, raw.subarray(0, 12));
    cipher.setAuthTag(raw.subarray(-16));
    const value = z
      .object({ bearer: z.string(), expires: z.number().int() })
      .parse(
        JSON.parse(
          Buffer.concat([cipher.update(raw.subarray(12, -16)), cipher.final()]).toString(),
        ),
      );
    if (
      typeof value.bearer !== "string" ||
      !Number.isSafeInteger(value.expires) ||
      value.expires <= Date.now()
    )
      throw new Error("expired_ticket");
    return value;
  }
  private async session(headers: Headers, ticket = false) {
    let bearer = headers.get("authorization");
    if (!bearer?.startsWith("Bearer ")) throw new Error("unauthorized");
    if (ticket) bearer = this.open(bearer.slice(7)).bearer;
    const session = await this.readSession(new Headers({ authorization: bearer }));
    if (!session || session.mustChangePassword) throw new Error("unauthorized");
    return session;
  }
  private reply(value: unknown, status = 200) {
    return Response.json(value, { status, headers: { "cache-control": "no-store" } });
  }
  private get configured() {
    return Boolean(this.env["CLAWMUSE_STEP_API_KEY"]);
  }

  async handle(request: Request): Promise<Response> {
    try {
      const path = new URL(request.url).pathname.slice(prefix.length);
      const session = await this.session(
        request.headers,
        path === "/audio/asr/sse" || path === "/audio/speech",
      );
      if (path === "" && request.method === "GET") {
        const result = await this.database.query<{ seconds: string; pending: string }>(
          `SELECT COALESCE(SUM(seconds),0)::text AS seconds, COUNT(*) FILTER (WHERE state='active')::text AS pending FROM clawmuse_official_usage WHERE user_id=$1 AND service='realtime'`,
          [session.userId],
        );
        const used = Number(result.rows[0]?.seconds ?? 0);
        const free = Number(this.env["CLAWMUSE_VOICE_FREE_SECONDS"] ?? 1800);
        return this.reply({
          configured: this.configured,
          billingMode: "trial",
          paymentsEnabled: false,
          period: "lifetime",
          freeSeconds: free,
          usedSeconds: used,
          remainingSeconds: Math.max(0, free - used),
          promotionalSeconds: Math.max(0, used - free),
          pending: Number(result.rows[0]?.pending ?? 0),
          amountDue: 0,
        });
      }
      if (!this.configured) return this.reply({ error: "official_service_not_configured" }, 503);
      if (path === "/session" && request.method === "POST") {
        return this.reply({
          credential: this.seal(request.headers.get("authorization")!),
          baseUrl: this.origin.replace(/^http/, "ws") + prefix + "/realtime",
          httpBaseUrl: this.origin + prefix,
          model: this.env["CLAWMUSE_REALTIME_MODEL"] ?? "stepaudio-3-realtime-preview",
          expiresAt: Date.now() + 60 * 60 * 1000,
        });
      }
      if (request.method === "POST" && ["/audio/asr/sse", "/audio/speech"].includes(path))
        return await this.audio(request, session.userId, path);
      return this.reply({ error: "not_found" }, 404);
    } catch {
      return this.reply({ error: "official_request_failed" }, 401);
    }
  }

  private async audio(request: Request, userId: string, path: string): Promise<Response> {
    const chunks: Uint8Array[] = [];
    let size = 0;
    const reader = request.body?.getReader();
    if (!reader) return this.reply({ error: "audio_required" }, 400);
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 20 * 1024 * 1024) {
        await reader.cancel();
        return this.reply({ error: "audio_too_large" }, 413);
      }
      chunks.push(chunk.value);
    }
    const text = Buffer.concat(chunks).toString();
    const payload = z.record(z.string(), z.unknown()).parse(JSON.parse(text));
    payload["model"] =
      path === "/audio/speech"
        ? (this.env["CLAWMUSE_TTS_MODEL"] ?? "stepaudio-2.5-tts")
        : (this.env["CLAWMUSE_ASR_MODEL"] ?? "stepaudio-2.5-asr");
    if (path === "/audio/asr/sse") {
      const audio = z
        .object({
          data: z.string(),
          input: z.object({
            transcription: z.record(z.string(), z.unknown()),
            format: z.record(z.string(), z.unknown()),
          }),
        })
        .parse(payload["audio"]);
      audio.input.transcription["model"] = this.env["CLAWMUSE_ASR_MODEL"] ?? "stepaudio-2.5-asr";
      payload["audio"] = audio;
      delete payload["model"];
    }
    const id = await this.begin(userId, path);
    const started = Date.now();
    try {
      const response = await fetch(
        (this.env["CLAWMUSE_AUDIO_BASE_URL"] ?? "https://api.stepfun.com/step_plan/v1") + path,
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + this.env["CLAWMUSE_STEP_API_KEY"],
            "content-type": "application/json",
          },
          body: JSON.stringify(payload),
          redirect: "error",
          signal: AbortSignal.any([request.signal, AbortSignal.timeout(120000)]),
        },
      );
      if (!response.ok) {
        await response.body?.cancel();
        await this.finish(id, 0, "rejected");
        return this.reply({ error: "official_upstream_rejected" }, 502);
      }
      const data = await response.arrayBuffer();
      await this.finish(id, Math.ceil((Date.now() - started) / 1000), "completed");
      return new Response(data, {
        headers: {
          "content-type": response.headers.get("content-type") ?? "application/octet-stream",
          "cache-control": "no-store",
        },
      });
    } catch {
      await this.finish(id, 0, "unsettled");
      return this.reply({ error: "official_upstream_failed" }, 502);
    }
  }

  private async begin(userId: string, service: string): Promise<string> {
    return this.database.transaction(async (tx) => {
      await tx.query('SELECT id FROM "user" WHERE id=$1 FOR UPDATE', [userId]);
      const result = await tx.query<{ count: string }>(
        "SELECT COUNT(*)::text AS count FROM clawmuse_official_usage WHERE user_id=$1 AND state='active' AND started_at > now() - interval '1 hour'",
        [userId],
      );
      if (Number(result.rows[0]?.count ?? 0) >= 6) throw new Error("official_concurrency_limit");
      const recent = await tx.query<{ count: string }>(
        "SELECT COUNT(*)::text AS count FROM clawmuse_official_usage WHERE user_id=$1 AND started_at > now() - interval '1 minute'",
        [userId],
      );
      if (Number(recent.rows[0]?.count ?? 0) >= 60) throw new Error("official_rate_limit");
      const id = randomUUID();
      await tx.query(
        "INSERT INTO clawmuse_official_usage(id,user_id,service,state,seconds) VALUES($1,$2,$3,'active',0)",
        [id, userId, service],
      );
      return id;
    });
  }
  private async finish(id: string, seconds: number, state: string) {
    await this.database.query(
      "UPDATE clawmuse_official_usage SET seconds=$2,state=$3,ended_at=now() WHERE id=$1 AND state='active'",
      [id, seconds, state],
    );
  }

  async upgrade(request: IncomingMessage, socket: Duplex, head: Buffer): Promise<boolean> {
    if (new URL(request.url ?? "/", this.origin).pathname !== prefix + "/realtime") return false;
    try {
      if (!this.configured) throw new Error("unavailable");
      const authorization = request.headers.authorization;
      const headers = new Headers(authorization ? { authorization } : {});
      const ticket = this.open(authorization?.slice(7) ?? "");
      const session = await this.session(headers, true);
      const id = await this.begin(session.userId, "realtime");
      const started = Date.now();
      this.wss.handleUpgrade(request, socket, head, (client) => {
        this.sockets.add(client);
        const endpoint = new URL(
          this.env["CLAWMUSE_REALTIME_URL"] ?? "wss://api.stepfun.com/v1/realtime",
        );
        endpoint.searchParams.set(
          "model",
          this.env["CLAWMUSE_REALTIME_MODEL"] ?? "stepaudio-3-realtime-preview",
        );
        const upstream = new WebSocket(endpoint, {
          headers: { authorization: "Bearer " + this.env["CLAWMUSE_STEP_API_KEY"] },
          handshakeTimeout: 15000,
          maxPayload: 4 * 1024 * 1024,
        });
        let ended = false;
        const end = () => {
          if (ended) return;
          ended = true;
          clearInterval(check);
          clearTimeout(limit);
          this.sockets.delete(client);
          upstream.close();
          client.close(1000);
          void this.finish(id, Math.ceil((Date.now() - started) / 1000), "completed").catch(
            () => {},
          );
        };
        const limit = setTimeout(end, Math.min(60 * 60 * 1000, ticket.expires - Date.now()));
        const check = setInterval(() => {
          void this.session(headers, true).catch(end);
        }, 30000);
        const queue: Buffer[] = [];
        let bytes = 0;
        client.on("message", (data) => {
          let value: Buffer;
          if (Buffer.isBuffer(data)) value = data;
          else if (data instanceof ArrayBuffer) value = Buffer.from(data);
          else value = Buffer.concat(data);
          if (upstream.readyState === WebSocket.OPEN) {
            if (upstream.bufferedAmount > 4 * 1024 * 1024) end();
            else upstream.send(value, { binary: false });
          } else {
            bytes += value.length;
            if (bytes > 4 * 1024 * 1024) end();
            else queue.push(value);
          }
        });
        upstream.on("open", () => {
          for (const data of queue) upstream.send(data, { binary: false });
          queue.length = 0;
        });
        upstream.on("message", (data) => {
          if (client.readyState === WebSocket.OPEN) {
            if (client.bufferedAmount > 4 * 1024 * 1024) end();
            else client.send(data, { binary: false });
          }
        });
        client.on("close", end);
        client.on("error", end);
        upstream.on("close", end);
        upstream.on("error", end);
      });
      return true;
    } catch {
      socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      return true;
    }
  }
  close() {
    for (const socket of this.sockets) socket.close(1001);
    this.wss.close();
  }
}
