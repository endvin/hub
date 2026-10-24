import { z } from "zod";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, expect, it } from "vitest";
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

beforeAll(async () => {
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
  await auth?.close();
  await runtime?.close();
  if (directory) await rm(directory, { recursive: true, force: true });
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
