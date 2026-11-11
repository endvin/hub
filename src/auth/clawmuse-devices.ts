import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { z } from "zod";
import type { DatabaseRuntime } from "../db/runtime/index.js";
import type { AccountSession } from "./organization-access.js";

const deviceSchema = z
  .object({
    label: z.string().trim().min(1).max(100),
    accountKey: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/)
      .optional(),
    offer: z
      .object({
        v: z.literal(2),
        requiresAuthorization: z.boolean().optional(),
        minimumSecurityMode: z.literal("protected").optional(),
        serverId: z.string().regex(/^srv_[A-Za-z0-9_-]{1,100}$/),
        daemonPublicKeyB64: z.string().regex(/^[A-Za-z0-9+/]{43}=$/),
        relay: z.object({ endpoint: z.string().min(1).max(255), useTls: z.literal(true) }).strict(),
      })
      .strict(),
  })
  .strict();
const storedOfferSchema = deviceSchema.shape.offer.extend({
  accountKeyEnvelope: z.string().optional(),
});

/** ClawMuse's personal device directory is independent of Hub organization permissions.
 * Offers are connection capabilities: never log them or store their plaintext in PostgreSQL.
 * Removing a directory entry stops discovery; it does not revoke an already paired client.
 */
export class ClawMuseDevices {
  private readonly key: Buffer;
  private readonly relayEndpoints: ReadonlySet<string>;

  constructor(
    private readonly database: DatabaseRuntime,
    secret: string,
    relayEndpoints: readonly string[],
    private readonly readSession: (headers: Headers) => Promise<AccountSession | undefined>,
    private readonly cloudEnabled: (userId: string) => boolean = () => false,
  ) {
    this.key = Buffer.from(hkdfSync("sha256", secret, "", "clawmuse-device-directory-v1", 32));
    this.relayEndpoints = new Set(relayEndpoints);
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
        hidden: boolean;
        offer: string;
        updated_at: Date;
      }>(
        "SELECT server_id, label, hidden, offer, updated_at FROM clawmuse_devices WHERE user_id = $1 ORDER BY updated_at DESC",
        [session.userId],
      );
      return this.reply({
        account: { id: session.userId, name: session.name, email: session.email },
        ...(this.cloudEnabled(session.userId) ? { cloud: { enabled: true } } : {}),
        devices: result.rows.map((row) => {
          const { accountKeyEnvelope, ...offer } = this.decryptOffer(
            row.offer,
            session.userId,
            row.server_id,
          );
          return {
            serverId: row.server_id,
            label: row.label,
            hidden: row.hidden,
            offer,
            accountAuthorization: !!accountKeyEnvelope,
            updatedAt: row.updated_at,
          };
        }),
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
    if (path === "/api/auth/clawmuse/devices/authorize")
      return this.authorize(body, session.userId);
    if (path === "/api/auth/clawmuse/devices/visibility") {
      return this.setVisibility(body, session.userId);
    }
    if (path === "/api/auth/clawmuse/devices/rename") {
      const input = z
        .object({
          serverId: deviceSchema.shape.offer.shape.serverId,
          label: deviceSchema.shape.label,
        })
        .strict()
        .safeParse(body);
      if (!input.success) return this.reply({ error: "invalid_request" }, 400);
      const result = await this.database.query(
        "UPDATE clawmuse_devices SET label = $1, updated_at = now() WHERE user_id = $2 AND server_id = $3 RETURNING server_id",
        [input.data.label, session.userId, input.data.serverId],
      );
      return result.rowCount
        ? this.reply({ ok: true })
        : this.reply({ error: "device_not_found" }, 404);
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
    return this.enroll(body, session.userId);
  }

  private async enroll(body: unknown, userId: string): Promise<Response> {
    const input = deviceSchema.safeParse(body);
    if (!input.success || !this.relayEndpoints.has(input.data.offer.relay.endpoint)) {
      return this.reply({ error: "invalid_device" }, 400);
    }
    const { label, offer } = input.data;
    if (
      input.data.accountKey &&
      (!offer.requiresAuthorization || offer.minimumSecurityMode !== "protected")
    )
      return this.reply({ error: "invalid_device" }, 400);
    return this.database.transaction(async (tx) => {
      // Serialize a user's enrollments so concurrent requests cannot exceed the quota.
      await tx.query('SELECT id FROM "user" WHERE id = $1 FOR UPDATE', [userId]);
      const existing = await tx.query<{ user_id: string; offer: string }>(
        "SELECT user_id, offer FROM clawmuse_devices WHERE server_id = $1",
        [offer.serverId],
      );
      if (existing.rows[0] && existing.rows[0].user_id !== userId) {
        return this.reply({ error: "device_already_owned" }, 409);
      }
      const previous = existing.rows[0]
        ? this.decryptOffer(existing.rows[0].offer, userId, offer.serverId)
        : null;
      // Older Hub versions return unknown offer fields. Keep the signing key encrypted even
      // inside that payload so rolling back the Hub cannot disclose it to account clients.
      let accountKeyEnvelope = input.data.accountKey
        ? this.encrypt(JSON.stringify(input.data.accountKey), userId, `${offer.serverId}:account`)
        : undefined;
      if (!accountKeyEnvelope && previous?.accountKeyEnvelope) {
        if (
          offer.daemonPublicKeyB64 !== previous.daemonPublicKeyB64 ||
          !offer.requiresAuthorization ||
          offer.minimumSecurityMode !== "protected"
        )
          return this.reply({ error: "device_identity_changed" }, 409);
        accountKeyEnvelope = previous.accountKeyEnvelope;
      }
      const count = await tx.query<{ count: string }>(
        "SELECT count(*) FROM clawmuse_devices WHERE user_id = $1",
        [userId],
      );
      if (!existing.rows[0] && Number(count.rows[0]?.count) >= 20)
        return this.reply({ error: "device_limit" }, 409);
      const result = await tx.query(
        `INSERT INTO clawmuse_devices (server_id, user_id, label, offer) VALUES ($1, $2, $3, $4)
         ON CONFLICT (server_id) DO UPDATE SET offer = EXCLUDED.offer, updated_at = now()
         WHERE clawmuse_devices.user_id = EXCLUDED.user_id RETURNING server_id`,
        [
          offer.serverId,
          userId,
          label,
          this.encrypt(JSON.stringify({ ...offer, accountKeyEnvelope }), userId, offer.serverId),
        ],
      );
      return result.rowCount
        ? this.reply({ ok: true })
        : this.reply({ error: "device_already_owned" }, 409);
    });
  }

  private async authorize(body: unknown, userId: string): Promise<Response> {
    const input = z
      .object({
        serverId: deviceSchema.shape.offer.shape.serverId,
        daemonPublicKeyB64: deviceSchema.shape.offer.shape.daemonPublicKeyB64,
        controllerHash: z.string().regex(/^[a-f0-9]{64}$/),
      })
      .strict()
      .safeParse(body);
    if (!input.success) return this.reply({ error: "invalid_request" }, 400);
    const result = await this.database.query<{ offer: string }>(
      "SELECT offer FROM clawmuse_devices WHERE user_id = $1 AND server_id = $2",
      [userId, input.data.serverId],
    );
    const row = result.rows[0];
    if (!row) return this.reply({ error: "device_not_found" }, 404);
    const offer = this.decryptOffer(row.offer, userId, input.data.serverId);
    if (!offer.accountKeyEnvelope)
      return this.reply({ error: "account_authorization_unavailable" }, 409);
    if (offer.daemonPublicKeyB64 !== input.data.daemonPublicKeyB64)
      return this.reply({ error: "device_identity_changed" }, 409);
    // The host pins this per-account key locally. The proof cannot authorize a different
    // host, account, or controller, and the controller's secret never reaches the Hub.
    const encoded = Buffer.from(
      JSON.stringify([
        "clawmuse-account-v1",
        input.data.serverId,
        userId,
        input.data.controllerHash,
        Date.now() + 90_000,
      ]),
    ).toString("base64url");
    const accountKey = deviceSchema.shape.accountKey
      .unwrap()
      .parse(this.decrypt(offer.accountKeyEnvelope, userId, `${input.data.serverId}:account`));
    const signature = createHmac("sha256", Buffer.from(accountKey, "base64url"))
      .update(encoded)
      .digest("base64url");
    return this.reply({ authorization: `${encoded}.${signature}` });
  }

  private async setVisibility(body: unknown, userId: string): Promise<Response> {
    const input = z
      .object({
        serverId: deviceSchema.shape.offer.shape.serverId,
        hidden: z.boolean(),
      })
      .strict()
      .safeParse(body);
    if (!input.success) return this.reply({ error: "invalid_request" }, 400);
    const result = await this.database.query(
      "UPDATE clawmuse_devices SET hidden = $1, updated_at = now() WHERE user_id = $2 AND server_id = $3 RETURNING server_id",
      [input.data.hidden, userId, input.data.serverId],
    );
    return result.rowCount
      ? this.reply({ ok: true })
      : this.reply({ error: "device_not_found" }, 404);
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

  private decryptOffer(value: string, userId: string, serverId: string) {
    return storedOfferSchema.parse(this.decrypt(value, userId, serverId));
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
