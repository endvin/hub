import { createServer } from "node:http";
import { createHash, createHmac } from "node:crypto";
import { z } from "zod";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, expect, it, vi } from "vitest";
import { embeddedDatabaseRuntime, type DatabaseRuntime } from "../db/runtime/index.js";
import { createDatabase } from "../db/pg.js";
import { composeEntitlements } from "./entitlements.js";
import { createAuthServer, type AuthServer } from "./server.js";

let auth: AuthServer;
let runtime: DatabaseRuntime;
let directory: string;
let firstToken: string;
let secondToken: string;
const base = "http://localhost:3000/api/auth";
const device = {
  label: "Test computer",
  offer: {
    v: 2,
    serverId: "srv_clawmuse_test",
    daemonPublicKeyB64: Buffer.alloc(32, 7).toString("base64"),
    relay: { endpoint: "agent-relay.ppb.cn:443", useTls: true },
  },
};
const call = (path: string, token?: string, body?: unknown) =>
  auth.handle(
    new Request(base + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
  );

const cloudSecret = "cloud-secret-123456789012345678901234567890";
const cloudRequests: { owner: string; path: string }[] = [];
let cloudCleanupOk = true;
const cloudServer = createServer((request, response) => {
  const owner = String(request.headers["x-clawmuse-owner"]);
  const time = String(request.headers["x-clawmuse-timestamp"]);
  const path = request.url!;
  const signature = createHmac("sha256", cloudSecret)
    .update([request.method, path, owner, time, ""].join("\n"))
    .digest("hex");
  expect(request.headers["x-clawmuse-signature"]).toBe(signature);
  expect(request.headers.authorization).toBeUndefined();
  cloudRequests.push({ owner, path });
  response.writeHead(path.endsWith("/delete") && !cloudCleanupOk ? 503 : 200, {
    "content-type": "application/json",
  });
  response.end(
    JSON.stringify(
      path.endsWith("/delete")
        ? { deleted: cloudCleanupOk }
        : { state: "pending_configuration", models: [], offer: null, balance: null },
    ),
  );
});

beforeAll(async () => {
  await new Promise<void>((resolve) => cloudServer.listen(0, "127.0.0.1", resolve));
  const address = cloudServer.address();
  if (!address || typeof address === "string") throw new Error("no_cloud_address");
  vi.stubEnv("CLAWMUSE_CLOUD_SERVICE_URL", `http://127.0.0.1:${address.port}`);
  vi.stubEnv("CLAWMUSE_CLOUD_SERVICE_SECRET", cloudSecret);
  vi.stubEnv(
    "CLAWMUSE_RELAY_ENDPOINTS",
    "agent-relay.clawmuse.com:443, agent-relay.ppb.cn:443,agent-relay-cn.clawmuse.com:443",
  );
  directory = await mkdtemp(join(tmpdir(), "clawmuse-account-test-"));
  const bundle = await embeddedDatabaseRuntime(directory);
  runtime = bundle.runtime;
  await runtime.migrate();
  const database = createDatabase(runtime, bundle.locks);
  const entitlements = composeEntitlements(database, runtime);
  auth = createAuthServer({
    database: runtime,
    locks: bundle.locks,
    entitlements: entitlements.service,
    secret: "clawmuse-test-secret-at-least-32-characters",
    baseURL: "http://localhost:3000",
    policy: { registrationMode: "open", organizationCreation: "disabled", bootstrap: undefined },
  });
  const signup = async (email: string) => {
    const response = await call("/sign-up/email", undefined, {
      name: "Test",
      email,
      password: "test-password-123456",
    });
    expect(response.status).toBe(200);
    const token = response.headers.get("set-auth-token");
    expect(token).toBeTruthy();
    return token!;
  };
  firstToken = await signup("first@example.test");
  secondToken = await signup("second@example.test");
}, 60000);

afterAll(async () => {
  vi.unstubAllEnvs();
  await new Promise<void>((resolve) => cloudServer.close(() => resolve()));
  await auth?.close();
  await runtime?.close();
  if (directory) await rm(directory, { recursive: true, force: true });
});

it("derives cloud ownership from bearer sessions and ignores client-selected identities", async () => {
  expect((await call("/clawmuse/cloud")).status).toBe(401);
  const first = await call("/clawmuse/devices", firstToken);
  const cloudDirectory = z
    .object({
      account: z.object({ id: z.string() }),
      cloud: z.object({ enabled: z.literal(true) }),
    })
    .parse(await first.json());
  const owner = createHash("sha256")
    .update(`clawmuse-cloud-user\0${cloudDirectory.account.id}`)
    .digest("hex");
  expect(
    (
      await call("/clawmuse/cloud/start", firstToken, {
        userId: "other-user",
        owner: "other-owner",
      })
    ).status,
  ).toBe(200);
  expect(cloudRequests.at(-1)).toEqual({ owner, path: "/internal/space/start" });
  expect((await call("/clawmuse/cloud", secondToken)).status).toBe(200);
  expect(cloudRequests.at(-1)?.owner).not.toBe(owner);
  expect((await call("/clawmuse/cloud/delete", firstToken, {})).status).toBe(404);
});

it("registers without organization onboarding and isolates each account's encrypted directory", async () => {
  expect((await call("/clawmuse/devices")).status).toBe(401);
  expect((await call("/clawmuse/devices", firstToken, device)).status).toBe(200);
  const first = z
    .object({ devices: z.array(z.object({ offer: z.unknown() })) })
    .parse(await (await call("/clawmuse/devices", firstToken)).json());
  expect(first.devices).toHaveLength(1);
  expect(first.devices[0]?.offer).toEqual(device.offer);
  const second = z
    .object({ devices: z.array(z.unknown()) })
    .parse(await (await call("/clawmuse/devices", secondToken)).json());
  expect(second.devices).toEqual([]);
  expect((await call("/clawmuse/devices", secondToken, device)).status).toBe(409);
  await call("/clawmuse/devices/remove", secondToken, { serverId: device.offer.serverId });
  expect(
    z
      .object({ devices: z.array(z.unknown()) })
      .parse(await (await call("/clawmuse/devices", firstToken)).json()).devices,
  ).toHaveLength(1);
  const stored = await runtime.query<{ offer: string }>("SELECT offer FROM clawmuse_devices");
  expect(stored.rows[0]!.offer).not.toContain(device.offer.daemonPublicKeyB64);
  expect(stored.rows[0]!.offer).not.toContain("relay");
});

it("rejects injected relay endpoints and unsigned sessions", async () => {
  expect(
    (
      await call("/clawmuse/devices", firstToken, {
        ...device,
        offer: { ...device.offer, relay: { endpoint: "localhost:6767", useTls: true } },
      })
    ).status,
  ).toBe(400);
  expect((await call("/clawmuse/devices", "fake")).status).toBe(401);
});

it.each(["agent-relay.clawmuse.com:443", "agent-relay-cn.clawmuse.com:443"])(
  "accepts %s and preserves the original endpoint in discovery",
  async (endpoint) => {
    const modern = {
      ...device,
      offer: {
        ...device.offer,
        serverId: "srv_clawmuse_new_domain",
        relay: { endpoint, useTls: true },
      },
    };
    expect((await call("/clawmuse/devices", firstToken, modern)).status).toBe(200);
    const result = z
      .object({ devices: z.array(z.object({ serverId: z.string(), offer: z.unknown() })) })
      .parse(await (await call("/clawmuse/devices", firstToken)).json());
    expect(result.devices.find((item) => item.serverId === modern.offer.serverId)?.offer).toEqual(
      modern.offer,
    );
    await call("/clawmuse/devices/remove", firstToken, { serverId: modern.offer.serverId });
    for (const rejectedEndpoint of [
      "agent-relay.clawmuse.com.evil.test:443",
      "agent-relay.clawmuse.com:80",
    ]) {
      expect(
        (
          await call("/clawmuse/devices", firstToken, {
            ...modern,
            offer: { ...modern.offer, relay: { endpoint: rejectedEndpoint, useTls: true } },
          })
        ).status,
      ).toBe(400);
    }
  },
);

it("shares explicit renames and preserves them across stale device enrollment", async () => {
  const phoneSession = await call("/sign-in/email", undefined, {
    email: "first@example.test",
    password: "test-password-123456",
  });
  expect(phoneSession.status).toBe(200);
  const phoneToken = phoneSession.headers.get("set-auth-token")!;
  await call("/clawmuse/devices", firstToken, device);
  const rename = { serverId: device.offer.serverId, label: "  Office Mac  " };
  expect((await call("/clawmuse/devices/rename", firstToken, rename)).status).toBe(200);
  expect((await call("/clawmuse/devices", firstToken, device)).status).toBe(200);
  const phoneDirectory = z
    .object({ devices: z.array(z.object({ label: z.string(), offer: z.unknown() })) })
    .parse(await (await call("/clawmuse/devices", phoneToken)).json());
  expect(phoneDirectory.devices[0]?.label).toBe("Office Mac");
  expect(phoneDirectory.devices[0]?.offer).toEqual(device.offer);

  expect((await call("/clawmuse/devices/rename", secondToken, rename)).status).toBe(404);
  expect(
    (await call("/clawmuse/devices/rename", firstToken, { ...rename, serverId: "srv_missing" }))
      .status,
  ).toBe(404);
  for (const label of [" ", "x".repeat(101)]) {
    expect((await call("/clawmuse/devices/rename", firstToken, { ...rename, label })).status).toBe(
      400,
    );
  }
  const stored = await runtime.query<{ label: string }>(
    "SELECT label FROM clawmuse_devices WHERE server_id = $1",
    [device.offer.serverId],
  );
  expect(stored.rows[0]?.label).toBe("Office Mac");
});

it("revokes the account session on logout", async () => {
  expect((await call("/sign-out", secondToken, {})).status).toBe(200);
  expect((await call("/clawmuse/devices", secondToken)).status).toBe(401);
});

it("stores protected device identities without admitting pairing invitations into the account directory", async () => {
  const protectedDevice = {
    ...device,
    offer: {
      ...device.offer,
      serverId: "srv_clawmuse_protected",
      requiresAuthorization: true,
      minimumSecurityMode: "protected",
    },
  };
  expect((await call("/clawmuse/devices", firstToken, protectedDevice)).status).toBe(200);
  const directoryResult = z
    .object({ devices: z.array(z.object({ serverId: z.string(), offer: z.unknown() })) })
    .parse(await (await call("/clawmuse/devices", firstToken)).json());
  expect(
    directoryResult.devices.find((entry) => entry.serverId === protectedDevice.offer.serverId)
      ?.offer,
  ).toEqual(protectedDevice.offer);
  expect(
    (
      await call("/clawmuse/devices", firstToken, {
        ...protectedDevice,
        offer: {
          ...protectedDevice.offer,
          pairing: { token: "secret", expiresAt: "2026-10-26T00:10:00Z" },
        },
      })
    ).status,
  ).toBe(400);
});

it("serves the browser client from the app origin with bearer sessions only", async () => {
  const app = "https://app.clawmuse.com";
  const browser = (
    path: string,
    origin: string,
    init: { method?: string; headers?: Record<string, string>; body?: string } = {},
  ) =>
    auth.handle(
      new Request(base + path, {
        ...init,
        headers: {
          origin,
          "sec-fetch-site": "same-site",
          "sec-fetch-mode": "cors",
          ...init.headers,
        },
      }),
    );
  const credentials = JSON.stringify({
    email: "first@example.test",
    password: "test-password-123456",
  });
  const json = { "content-type": "application/json" };

  const preflight = await browser("/sign-in/email", app, { method: "OPTIONS" });
  expect(preflight.status).toBe(204);
  expect(preflight.headers.get("access-control-allow-origin")).toBe(app);
  expect(preflight.headers.get("access-control-allow-headers")).toContain("authorization");
  const foreign = await browser("/sign-in/email", "https://evil.test", {
    method: "POST",
    headers: json,
    body: credentials,
  });
  // Better Auth skips its own origin check under NODE_ENV=test; only the CORS grant is asserted.
  expect(foreign.headers.get("access-control-allow-origin")).toBeNull();

  const signIn = await browser("/sign-in/email", app, {
    method: "POST",
    headers: json,
    body: credentials,
  });
  expect(signIn.status).toBe(200);
  expect(signIn.headers.get("access-control-allow-origin")).toBe(app);
  expect(signIn.headers.get("access-control-expose-headers")).toBe("set-auth-token");
  expect(signIn.headers.get("set-cookie")).toBeNull();
  const token = signIn.headers.get("set-auth-token")!;
  expect(token).toBeTruthy();
  const devices = await browser("/clawmuse/devices", app, {
    headers: { authorization: `Bearer ${token}` },
  });
  expect(devices.status).toBe(200);
  expect(devices.headers.get("access-control-allow-origin")).toBe(app);

  const cookieSession = await call("/sign-in/email", undefined, JSON.parse(credentials));
  const cookie = cookieSession.headers.get("set-cookie")!.split(";")[0]!;
  expect(
    (await browser("/get-session", app, { headers: { cookie } }).then((r) => r.json())) as unknown,
  ).toBeNull();

  expect(
    (
      await browser("/sign-out", app, {
        method: "POST",
        headers: { ...json, authorization: `Bearer ${token}` },
        body: "{}",
      })
    ).status,
  ).toBe(200);
  expect((await call("/clawmuse/devices", token)).status).toBe(401);
});

it("reauthenticates deletion, waits for personal status cleanup, and revokes every session", async () => {
  let cleanupOk = false;
  const cleanupRequests: unknown[] = [];
  const cleanup = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: unknown) => {
      if (Buffer.isBuffer(chunk)) chunks.push(chunk);
    });
    request.on("end", () => {
      cleanupRequests.push(JSON.parse(Buffer.concat(chunks).toString()));
      expect(request.headers.authorization).toBe("Bearer deletion-secret-at-least-32-characters");
      response.writeHead(cleanupOk ? 200 : 503, { "content-type": "application/json" });
      response.end(JSON.stringify(cleanupOk ? { deleted: true } : { error: "unavailable" }));
    });
  });
  await new Promise<void>((resolve) => cleanup.listen(0, "127.0.0.1", resolve));
  const address = cleanup.address();
  if (!address || typeof address === "string") throw new Error("missing test port");
  vi.stubEnv(
    "CLAWMUSE_STATUS_ACCOUNT_DELETION_URL",
    `http://127.0.0.1:${address.port}/v1/internal/accounts/delete`,
  );
  vi.stubEnv("ACCOUNT_DELETION_SECRET", "deletion-secret-at-least-32-characters");
  try {
    const login = await call("/sign-in/email", undefined, {
      email: "first@example.test",
      password: "test-password-123456",
    });
    const extraToken = login.headers.get("set-auth-token")!;
    expect(extraToken).toBeTruthy();
    expect((await call("/delete-user/", extraToken, {})).status).toBe(404);
    expect((await call("/delete-user", extraToken, {})).status).toBe(400);
    expect((await call("/delete-user", extraToken, { token: "email-token" })).status).toBe(400);
    expect((await call("/delete-user", firstToken, {})).status).toBe(400);
    expect((await call("/delete-user", firstToken, { password: "incorrect" })).status).toBe(400);
    expect(cleanupRequests).toEqual([]);
    expect(
      (await call("/delete-user", firstToken, { password: "test-password-123456" })).status,
    ).toBe(503);
    expect((await call("/clawmuse/devices", firstToken)).status).toBe(200);
    cleanupOk = true;
    cloudCleanupOk = false;
    expect(
      (await call("/delete-user", firstToken, { password: "test-password-123456" })).status,
    ).toBe(503);
    expect((await call("/clawmuse/devices", firstToken)).status).toBe(200);
    cloudCleanupOk = true;
    const deleted = await call("/delete-user", firstToken, { password: "test-password-123456" });
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ success: true, message: "User deleted" });
    expect(cleanupRequests).toHaveLength(3);
    expect(cleanupRequests[0]).toEqual(cleanupRequests[1]);
    expect((await call("/clawmuse/devices", firstToken)).status).toBe(401);
    expect((await call("/clawmuse/devices", extraToken)).status).toBe(401);
    const users = await runtime.query(`SELECT id FROM "user" WHERE email = $1`, [
      "first@example.test",
    ]);
    expect(users.rows).toEqual([]);
    const other = await call("/sign-in/email", undefined, {
      email: "second@example.test",
      password: "test-password-123456",
    });
    expect(other.status).toBe(200);
    expect((await call("/clawmuse/devices", other.headers.get("set-auth-token")!)).status).toBe(
      200,
    );
  } finally {
    await new Promise<void>((resolve) => cleanup.close(() => resolve()));
  }
});
