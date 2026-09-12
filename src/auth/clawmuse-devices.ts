import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { z } from "zod";
import type { DatabaseRuntime } from "../db/runtime/index.js";
import type { AccountSession } from "./organization-access.js";

const deviceSchema = z
  .object({
    label: z.string().trim().min(1).max(100),
    offer: z
      .object({
        v: z.literal(2),
        serverId: z.string().regex(/^srv_[A-Za-z0-9_-]{1,100}$/),
        daemonPublicKeyB64: z.string().regex(/^[A-Za-z0-9+/]{43}=$/),
        relay: z.object({ endpoint: z.string().min(1).max(255), useTls: z.literal(true) }).strict(),
      })
      .strict(),
  })
  .strict();

/** ClawMuse's personal device directory is independent of Hub organization permissions.
 * Offers are connection capabilities: never log them or store their plaintext in PostgreSQL.
 * Removing a directory entry stops discovery; it does not revoke an already paired client.
 */
export class ClawMuseDevices {
  private readonly key: Buffer;

  constructor(
    private readonly database: DatabaseRuntime,
    secret: string,
    private readonly relayEndpoint: string,
    private readonly readSession: (headers: Headers) => Promise<AccountSession | undefined>,
  ) {
    this.key = Buffer.from(hkdfSync("sha256", secret, "", "clawmuse-device-directory-v1", 32));
  }

  async handle(request: Request): Promise<Response> {
    // This API deliberately accepts bearer sessions only, so cross-site cookies cannot enroll
    // a computer into an account. The existing browser Hub keeps its cookie/CSRF contract.
    if (!request.headers.get("authorization")?.startsWith("Bearer ")) {
      return this.reply({ error: "unauthorized" }, 401);
    }
    const headers = new Headers(request.headers);
    headers.delete("cookie");
    const session = await this.readSession(headers);
    if (!session) return this.reply({ error: "unauthorized" }, 401);
    if (session.mustChangePassword) return this.reply({ error: "password_change_required" }, 403);
    const path = new URL(request.url).pathname;
    if (path === "/api/auth/clawmuse/devices" && request.method === "GET") {
      const result = await this.database.query<{
        server_id: string;
        label: string;
        offer: string;
        updated_at: Date;
      }>(
        "SELECT server_id, label, offer, updated_at FROM clawmuse_devices WHERE user_id = $1 ORDER BY updated_at DESC",
        [session.userId],
      );
      return this.reply({
        account: { id: session.userId, name: session.name, email: session.email },
        devices: result.rows.map((row) => ({
          serverId: row.server_id,
          label: row.label,
          offer: this.decrypt(row.offer, session.userId, row.server_id),
          updatedAt: row.updated_at,
        })),
      });
    }
    if (request.method !== "POST") return this.reply({ error: "not_found" }, 404);
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 4096) return this.reply({ error: "payload_too_large" }, 413);
    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return this.reply({ error: "invalid_request" }, 400);
    }
    if (path === "/api/auth/clawmuse/devices/remove") {
      const input = z
        .object({ serverId: z.string().max(110) })
        .strict()
        .safeParse(body);
      if (!input.success) return this.reply({ error: "invalid_request" }, 400);
      await this.database.query(
        "DELETE FROM clawmuse_devices WHERE user_id = $1 AND server_id = $2",
        [session.userId, input.data.serverId],
      );
      return this.reply({ ok: true });
    }
    if (path !== "/api/auth/clawmuse/devices") return this.reply({ error: "not_found" }, 404);
    const input = deviceSchema.safeParse(body);
    if (!input.success || input.data.offer.relay.endpoint !== this.relayEndpoint) {
      return this.reply({ error: "invalid_device" }, 400);
    }
    const { label, offer } = input.data;
    return this.database.transaction(async (tx) => {
      // Serialize a user's enrollments so concurrent requests cannot exceed the quota.
      await tx.query('SELECT id FROM "user" WHERE id = $1 FOR UPDATE', [session.userId]);
      const existing = await tx.query<{ user_id: string }>(
        "SELECT user_id FROM clawmuse_devices WHERE server_id = $1",
        [offer.serverId],
      );
      if (existing.rows[0] && existing.rows[0].user_id !== session.userId) {
        return this.reply({ error: "device_already_owned" }, 409);
      }
      const count = await tx.query<{ count: string }>(
        "SELECT count(*) FROM clawmuse_devices WHERE user_id = $1",
        [session.userId],
      );
      if (!existing.rows[0] && Number(count.rows[0]?.count) >= 20)
        return this.reply({ error: "device_limit" }, 409);
      const result = await tx.query(
        `INSERT INTO clawmuse_devices (server_id, user_id, label, offer) VALUES ($1, $2, $3, $4)
         ON CONFLICT (server_id) DO UPDATE SET label = EXCLUDED.label, offer = EXCLUDED.offer, updated_at = now()
         WHERE clawmuse_devices.user_id = EXCLUDED.user_id RETURNING server_id`,
        [
          offer.serverId,
          session.userId,
          label,
          this.encrypt(JSON.stringify(offer), session.userId, offer.serverId),
        ],
      );
      return result.rowCount
        ? this.reply({ ok: true })
        : this.reply({ error: "device_already_owned" }, 409);
    });
  }

  private encrypt(plaintext: string, userId: string, serverId: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(JSON.stringify([userId, serverId])));
    return Buffer.concat([
      iv,
      cipher.update(plaintext),
      cipher.final(),
      cipher.getAuthTag(),
    ]).toString("base64");
  }

  private decrypt(value: string, userId: string, serverId: string): unknown {
    const data = Buffer.from(value, "base64");
    const decipher = createDecipheriv("aes-256-gcm", this.key, data.subarray(0, 12));
    decipher.setAAD(Buffer.from(JSON.stringify([userId, serverId])));
    decipher.setAuthTag(data.subarray(-16));
    return JSON.parse(
      Buffer.concat([decipher.update(data.subarray(12, -16)), decipher.final()]).toString("utf8"),
    );
  }

  private reply(body: unknown, status = 200): Response {
    return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
  }
}
