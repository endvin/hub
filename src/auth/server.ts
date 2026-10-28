import { APIError } from "better-auth/api";
import { bearer } from "better-auth/plugins";
import { clawmuseAppOrigins, handleClawMuseAppRequest } from "./clawmuse-app-origin.js";
import { ClawMuseDevices } from "./clawmuse-devices.js";
import { ClawMuseCloud, clawmuseCloudConfig } from "./clawmuse-cloud.js";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { tanstackStartCookies } from "better-auth/tanstack-start";
import { z } from "zod";
import * as schema from "../db/schema.js";
import type { DatabaseRuntime } from "../db/runtime/index.js";
import type { Locks } from "../db/runtime/locks/index.js";
import { OrganizationApiKeys } from "./api-keys.js";
import { OrganizationCliCredentials } from "./cli-credentials.js";
import { PublicCredentialAuthenticator } from "./public-credentials.js";
import {
  InstanceSetup,
  type InitialOperator,
  type InstanceClaim,
} from "../instance-setup/index.js";
import {
  defaultInstanceAuthPolicy,
  PASSWORD_MIN_LENGTH,
  type InstanceAuthPolicy,
} from "./instance-policy.js";
import { RegistrationAdmission, RegistrationAdmissionError } from "./registration-admission.js";
import type {
  OrganizationResourceReader,
  OrganizationResources,
} from "../organizations/resources.js";
import {
  OrganizationAccess,
  type AccountAccessValue,
  type AccountSession,
  type OrganizationAccessValue,
} from "./organization-access.js";
import type { OrganizationCreatedEvent } from "../organizations/signup-intent.js";
import { paseoOrganizationPlugin } from "./organization-policy.js";
import type { EntitlementsService } from "../entitlements/service.js";
import {
  UNLIMITED_PROVISIONING,
  type ProvisioningEntitlementResolver,
} from "../organizations/provisioning.js";
import { InstanceAppOnboarding } from "../instance-setup/app-onboarding.js";
import { TRUSTED_REQUEST_ORIGIN_HEADER } from "../http/request-origin.js";
import type { InvitationMailer } from "../invitations/index.js";
import type { AccountMailer } from "./account-emails.js";

export interface AuthServer {
  handle(request: Request): Promise<Response>;
  browserAccount?(request: Request): Promise<Response>;
  signInEmail?(data: { email: string; password: string }, headers: Headers): Promise<"complete">;
  signUpEmail?(
    data: { name: string; email: string; password: string },
    headers: Headers,
    invitationId?: string,
  ): Promise<"complete" | "verificationRequired">;
  sendVerificationEmail?(email: string, headers: Headers, invitationId?: string): Promise<void>;
  requestPasswordReset?(email: string, headers: Headers): Promise<void>;
  resetPassword?(data: { token: string; newPassword: string }, headers: Headers): Promise<void>;
  signOut?(headers: Headers): Promise<void>;
  changePassword?(
    data: { currentPassword: string; newPassword: string },
    headers: Headers,
  ): Promise<void>;
  /** Creates the first operator on a pristine instance and signs the browser in. */
  claimInstance?(operator: InitialOperator, headers: Headers): Promise<InstanceClaim>;
  completeAppOnboarding?(request: Request): Promise<void>;
  resources(
    request: Request,
    organizations: OrganizationResources,
  ): Promise<OrganizationResourceReader>;
  resolveOrganizationAccess(request: Request): Promise<OrganizationAccessValue>;
  resolveAccount(request: Request): Promise<AccountAccessValue>;
  rejectCookieMutation(request: Request): Response | undefined;
  initialize?(): Promise<void>;
  apiKeys?: OrganizationApiKeys;
  cliCredentials?: OrganizationCliCredentials;
  publicCredentials?: PublicCredentialAuthenticator;
  close(): Promise<void>;
}

export interface AuthServerOptions {
  database: DatabaseRuntime;
  locks: Locks;
  /** Owned by the composition root, injected here — auth consumes entitlements, never owns them. */
  entitlements: EntitlementsService;
  secret: string;
  baseURL: string;
  policy?: InstanceAuthPolicy;
  trustedClientIpHeader?: string;
  /** How a new organization is provisioned. Defaults to unlimited (self-hosted); the composition
   * root passes a billing-backed resolver when Stripe is configured. */
  provisioningEntitlements?: ProvisioningEntitlementResolver;
  /** Post-commit hook awaited after organization creation. Integration failures must never fail
   * or roll back the successfully created organization. Undefined self-hosted. */
  onOrganizationCreated?: (event: OrganizationCreatedEvent) => Promise<void>;
  /** Post-commit hook fired when a membership change alters an organization's seat count. The
   * composition root wires billing's seat-quantity reporter here; undefined self-hosted. */
  onMembershipChanged?: (organizationId: string) => Promise<void>;
  /** Optional post-commit delivery for organization invitations. */
  invitationMailer?: InvitationMailer;
  /** Optional account email delivery. Configured public instances require verification. */
  accountMailer?: AccountMailer;
}

const sessionSchema = z.object({
  session: z
    .object({
      id: z.string(),
      userId: z.string(),
      activeOrganizationId: z.string().nullable().optional(),
    })
    .passthrough(),
  user: z
    .object({
      id: z.string(),
      name: z.string(),
      email: z.string(),
      mustChangePassword: z.boolean().optional(),
      isInstanceOperator: z.boolean().optional(),
    })
    .passthrough(),
});

const RAW_PRODUCT_PATHS = new Set([
  "/api/auth/get-session",
  "/api/auth/sign-up/email",
  "/api/auth/sign-in/email",
  "/api/auth/request-password-reset",
  "/api/auth/sign-out",
  "/api/auth/change-password",
  "/api/auth/verify-email",
]);

export function createAuthServer(options: AuthServerOptions): AuthServer {
  const database = options.database.drizzle();
  const policy = options.policy ?? defaultInstanceAuthPolicy();
  const provisioningEntitlements =
    options.provisioningEntitlements ?? (() => Promise.resolve(UNLIMITED_PROVISIONING));
  const apiKeys = new OrganizationApiKeys(options.database, options.locks);
  const cliCredentials = new OrganizationCliCredentials(options.database);
  const publicCredentials = new PublicCredentialAuthenticator(apiKeys, cliCredentials);
  const registration = new RegistrationAdmission(options.database, options.locks, policy);
  const instanceSetup = new InstanceSetup({
    database: options.database,
    policy,
    provisioningEntitlements,
  });
  const appOnboarding = new InstanceAppOnboarding(options.database);
  const accountMailer = options.accountMailer;
  const authSchema = {
    user: schema.users,
    session: schema.sessions,
    account: schema.accounts,
    verification: schema.verifications,
    organization: schema.organizations,
    member: schema.members,
    invitation: schema.invitations,
  };
  const cloud = new ClawMuseCloud(clawmuseCloudConfig(), (headers) => sessions.read(headers));
  const auth = betterAuth({
    baseURL: options.baseURL,
    secret: options.secret,
    ...(options.trustedClientIpHeader === undefined
      ? {}
      : {
          advanced: {
            ipAddress: {
              ipAddressHeaders: [options.trustedClientIpHeader],
            },
          },
        }),
    database: drizzleAdapter(database, { provider: "pg", schema: authSchema }),
    emailAndPassword: {
      enabled: true,
      minPasswordLength: PASSWORD_MIN_LENGTH,
      requireEmailVerification: accountMailer !== undefined,
      revokeSessionsOnPasswordReset: true,
      ...(accountMailer === undefined
        ? {}
        : { sendResetPassword: (email) => accountMailer.sendPasswordReset(email) }),
    },
    ...(accountMailer === undefined
      ? {}
      : {
          emailVerification: {
            autoSignInAfterVerification: true,
            // Signing in unverified resends the link, so a lost email never strands the account.
            sendOnSignIn: true,
            sendVerificationEmail: (email: Parameters<AccountMailer["sendVerificationEmail"]>[0]) =>
              accountMailer.sendVerificationEmail(email),
          },
        }),
    user: {
      deleteUser: {
        enabled: true,
        beforeDelete: async (user, request) => {
          // Keep future internal API callers and normalized callback paths behind the
          // same app-only password-verifying route, rather than fresh-session deletion.
          if (
            !request ||
            request.method !== "POST" ||
            new URL(request.url).pathname !== "/api/auth/delete-user" ||
            !request.headers.get("authorization")?.startsWith("Bearer ")
          ) {
            throw new APIError("FORBIDDEN", {
              message: "Use the password-confirmed account deletion flow.",
            });
          }
          // Shared Hub resources need an ownership transfer before the identity disappears.
          const ownership = await options.database.query(
            `SELECT 1 FROM member WHERE user_id = $1 AND role = 'owner'
             UNION ALL SELECT 1 FROM instance_bootstrap WHERE owner_user_id = $1
             UNION ALL SELECT 1 FROM "user" WHERE id = $1 AND is_instance_operator = true LIMIT 1`,
            [user.id],
          );
          if (ownership.rows.length > 0) {
            throw new APIError("CONFLICT", {
              message: "Transfer Hub ownership before deleting this account.",
              code: "ACCOUNT_OWNS_RESOURCES",
            });
          }
          const url = process.env["CLAWMUSE_STATUS_ACCOUNT_DELETION_URL"];
          const secret = process.env["ACCOUNT_DELETION_SECRET"];
          if (!url || !secret || secret.length < 32) {
            throw new APIError("SERVICE_UNAVAILABLE", {
              message: "Account deletion is temporarily unavailable.",
              code: "ACCOUNT_DELETION_UNAVAILABLE",
            });
          }
          const endpoint = new URL(url);
          if (
            endpoint.protocol !== "https:" &&
            !["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname)
          ) {
            throw new APIError("SERVICE_UNAVAILABLE", {
              message: "Account deletion is temporarily unavailable.",
            });
          }
          try {
            const response = await fetch(endpoint, {
              method: "POST",
              headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
              body: JSON.stringify({ userId: user.id }),
              redirect: "error",
              signal: AbortSignal.timeout(10000),
            });
            const result: unknown = await response.json();
            if (!response.ok || !z.object({ deleted: z.literal(true) }).safeParse(result).success)
              throw new Error("deletion_failed");
            await cloud.deleteAccount(user.id);
          } catch {
            throw new APIError("SERVICE_UNAVAILABLE", {
              message: "Account deletion could not finish. Retry; your account is still active.",
              code: "ACCOUNT_DELETION_UNAVAILABLE",
            });
          }
        },
      },
      additionalFields: {
        mustChangePassword: {
          type: "boolean",
          defaultValue: false,
          input: false,
          returned: true,
        },
        // The instance operator flag: read into the session so cross-org operator authorization
        // resolves from it. Granted only by instance setup or SQL — never client input — so
        // `input: false` keeps it off every sign-up/update body. Threaded like mustChangePassword.
        isInstanceOperator: {
          type: "boolean",
          defaultValue: false,
          input: false,
          returned: true,
        },
      },
    },
    plugins: [
      paseoOrganizationPlugin(),
      bearer({ requireSignature: true }),
      tanstackStartCookies(),
    ],
  });
  const sessions = {
    async read(headers: Headers): Promise<AccountSession | undefined> {
      const value = await auth.api.getSession({ headers });
      const parsed = sessionSchema.safeParse(value);
      if (!parsed.success) return undefined;
      return {
        sessionId: parsed.data.session.id,
        userId: parsed.data.user.id,
        name: parsed.data.user.name,
        email: parsed.data.user.email,
        activeOrganizationId: parsed.data.session.activeOrganizationId ?? null,
        mustChangePassword: parsed.data.user.mustChangePassword ?? false,
        isInstanceOperator: parsed.data.user.isInstanceOperator ?? false,
      };
    },
  };
  const access = new OrganizationAccess({
    pool: options.database,
    locks: options.locks,
    sessions,
    baseURL: options.baseURL,
    policy,
    apiKeys,
    cliCredentials,
    entitlements: options.entitlements,
    instanceSetup,
    appOnboarding,
    provisioningEntitlements,
    ...(options.onOrganizationCreated === undefined
      ? {}
      : { onOrganizationCreated: options.onOrganizationCreated }),
    ...(options.onMembershipChanged === undefined
      ? {}
      : { onMembershipChanged: options.onMembershipChanged }),
    ...(options.invitationMailer === undefined
      ? {}
      : { invitationMailer: options.invitationMailer }),
  });
  const clawmuseDevices = new ClawMuseDevices(
    options.database,
    options.secret,
    (
      process.env["CLAWMUSE_RELAY_ENDPOINTS"] ??
      process.env["CLAWMUSE_RELAY_ENDPOINT"] ??
      "agent-relay.clawmuse.com:443,agent-relay.ppb.cn:443"
    )
      .split(",")
      .map((endpoint) => endpoint.trim())
      .filter(Boolean),
    (headers) => sessions.read(headers),
    (userId) => cloud.enabledFor(userId),
  );
  cloud.start();
  const browserOrigin = new URL(options.baseURL).origin;
  const appOrigins = clawmuseAppOrigins(process.env["CLAWMUSE_APP_ORIGINS"]);
  const route = (request: Request): Promise<Response> => {
    const path = new URL(request.url).pathname;
    if (path === "/api/auth/delete-user") {
      // Password reauthentication is mandatory even for a fresh session.
      if (
        request.method !== "POST" ||
        !request.headers.get("authorization")?.startsWith("Bearer ")
      ) {
        return Promise.resolve(Response.json({ error: "unauthorized" }, { status: 401 }));
      }
      return request
        .clone()
        .json()
        .catch(() => null)
        .then((body: unknown) => {
          const input = z
            .object({ password: z.string().min(1).max(1024) })
            .strict()
            .safeParse(body);
          if (!input.success) return Response.json({ error: "password_required" }, { status: 400 });
          const headers = new Headers(request.headers);
          headers.delete("cookie");
          return auth.handler(
            new Request(request.url, { method: "POST", headers, body: JSON.stringify(input.data) }),
          );
        });
    }
    if (path === "/api/auth/clawmuse/cloud" || path.startsWith("/api/auth/clawmuse/cloud/"))
      return cloud.handle(request);
    if (path.startsWith("/api/auth/clawmuse/")) return clawmuseDevices.handle(request);
    if (path.startsWith("/api/auth/paseo/")) {
      const rejected = rejectCrossOriginCookieMutation(
        request,
        requestBrowserOrigin(request, browserOrigin),
      );
      if (rejected !== undefined) return Promise.resolve(rejected);
      return access.handle(request);
    }
    if (path === "/api/auth/sign-up/email") {
      return registration
        .handleSignUp(request, (admittedRequest) => auth.handler(admittedRequest))
        .catch((error: unknown) => {
          if (error instanceof RegistrationAdmissionError) {
            return Response.json({ error: "registration_closed" }, { status: 403 });
          }
          throw error;
        });
    }
    if (path === "/api/auth/change-password") {
      const rejected = rejectCrossOriginCookieMutation(
        request,
        requestBrowserOrigin(request, browserOrigin),
      );
      if (rejected !== undefined) return Promise.resolve(rejected);
      return changePassword(request);
    }
    if (!RAW_PRODUCT_PATHS.has(path) && !path.startsWith("/api/auth/reset-password/")) {
      return Promise.resolve(Response.json({ error: "not_found" }, { status: 404 }));
    }
    return auth.handler(request);
  };

  return {
    handle: (request) =>
      handleClawMuseAppRequest(request, appOrigins, browserOrigin, route) ?? route(request),
    browserAccount: (request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/auth/change-password") {
        const rejected = rejectCrossOriginCookieMutation(
          request,
          requestBrowserOrigin(request, browserOrigin),
        );
        return rejected === undefined ? changePassword(request) : Promise.resolve(rejected);
      }
      return access.handle(request);
    },
    async signInEmail(data, headers) {
      requireBrowserOrigin(headers, headersBrowserOrigin(headers, browserOrigin));
      await auth.api.signInEmail({ body: data, headers });
      return "complete";
    },
    async signUpEmail(data, headers, invitationId) {
      requireBrowserOrigin(headers, headersBrowserOrigin(headers, browserOrigin));
      await registration.withAdmission(data.email, invitationId, async () => {
        await auth.api.signUpEmail({
          body: { ...data, callbackURL: accountCallback(options.baseURL, invitationId) },
          headers,
        });
      });
      return accountMailer === undefined ? "complete" : "verificationRequired";
    },
    async sendVerificationEmail(email, headers, invitationId) {
      requireBrowserOrigin(headers, headersBrowserOrigin(headers, browserOrigin));
      await auth.api.sendVerificationEmail({
        body: { email, callbackURL: accountCallback(options.baseURL, invitationId) },
        headers,
      });
    },
    async requestPasswordReset(email, headers) {
      requireBrowserOrigin(headers, headersBrowserOrigin(headers, browserOrigin));
      await auth.api.requestPasswordReset({
        body: { email, redirectTo: passwordResetCallback(options.baseURL) },
        headers,
      });
    },
    async resetPassword(data, headers) {
      requireBrowserOrigin(headers, headersBrowserOrigin(headers, browserOrigin));
      await auth.api.resetPassword({ body: data, headers });
    },
    async claimInstance(operator, headers) {
      requireBrowserOrigin(headers, headersBrowserOrigin(headers, browserOrigin));
      const claim = await instanceSetup.claim(operator);
      if (claim.status !== "claimed") return claim;
      // The account exists and owns the instance the moment the claim commits; signing in here
      // is what turns that into the operator's browser session. A failure past this point costs
      // them a sign-in, never the claim.
      await auth.api.signInEmail({
        body: { email: operator.email, password: operator.password },
        headers,
      });
      return claim;
    },
    async completeAppOnboarding(request) {
      const rejected = rejectCrossOriginCookieMutation(
        request,
        requestBrowserOrigin(request, browserOrigin),
      );
      if (rejected !== undefined) throw new Error("invalid origin");
      const account = await access.account(request);
      if (!account.isInstanceOperator) throw new Error("forbidden");
      await appOnboarding.complete();
    },
    async signOut(headers) {
      requireBrowserOrigin(headers, headersBrowserOrigin(headers, browserOrigin));
      await auth.api.signOut({ headers });
    },
    async changePassword(data, headers) {
      requireBrowserOrigin(headers, headersBrowserOrigin(headers, browserOrigin));
      const session = await sessions.read(headers);
      if (session === undefined) throw new Error("unauthenticated");
      await auth.api.changePassword({
        body: { ...data, revokeOtherSessions: true },
        headers,
      });
      await options.database.query(
        `update "user" set must_change_password = false, updated_at = now() where id = $1`,
        [session.userId],
      );
    },
    async resources(request, organizations) {
      return access.resources(request, organizations);
    },
    resolveOrganizationAccess: (request) => access.resolve(request),
    resolveAccount: (request) => access.account(request),
    rejectCookieMutation: (request) =>
      rejectCrossOriginCookieMutation(request, requestBrowserOrigin(request, browserOrigin)),
    initialize: () => instanceSetup.initializeFromPolicy(),
    apiKeys,
    cliCredentials,
    publicCredentials,
    close: () => cloud.close(),
  };

  async function changePassword(request: Request): Promise<Response> {
    const session = await sessions.read(request.headers);
    const body = await request
      .clone()
      .json()
      .then((value: unknown) => value)
      .catch(() => undefined);
    const response =
      typeof body === "object" && body !== null
        ? await auth.handler(
            new Request(request.url, {
              method: "POST",
              headers: request.headers,
              body: JSON.stringify({ ...body, revokeOtherSessions: true }),
            }),
          )
        : await auth.handler(request);
    if (response.ok && session !== undefined) {
      await options.database.query(`update "user" set must_change_password = false where id = $1`, [
        session.userId,
      ]);
    }
    return response;
  }
}

function requestBrowserOrigin(request: Request, fallback: string): string {
  return headersBrowserOrigin(request.headers, fallback);
}

function accountCallback(baseURL: string, invitationId?: string): string {
  const callback = new URL("/", baseURL);
  callback.searchParams.set("auth", "email-verification");
  if (invitationId !== undefined) callback.searchParams.set("invitation", invitationId);
  return callback.toString();
}

function passwordResetCallback(baseURL: string): string {
  const callback = new URL("/", baseURL);
  callback.searchParams.set("auth", "password-reset");
  return callback.toString();
}

function headersBrowserOrigin(headers: Headers, fallback: string): string {
  const trusted = headers.get(TRUSTED_REQUEST_ORIGIN_HEADER);
  if (trusted === null) return fallback;
  const url = new URL(trusted);
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error("invalid trusted request origin");
  }
  return url.origin;
}

function requireBrowserOrigin(headers: Headers, browserOrigin: string): void {
  const suppliedOrigin = headers.get("origin") ?? headers.get("referer");
  if (suppliedOrigin === null || suppliedOrigin === "null") throw new Error("invalid origin");
  try {
    if (new URL(suppliedOrigin).origin === browserOrigin) return;
  } catch {
    // Invalid browser origins are rejected below.
  }
  throw new Error("invalid origin");
}

function rejectCrossOriginCookieMutation(
  request: Request,
  browserOrigin: string,
): Response | undefined {
  if (request.method !== "POST" || !request.headers.has("cookie")) return undefined;
  if (request.headers.get("sec-fetch-site") === "cross-site") {
    return authBoundaryError(
      "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
      "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
    );
  }
  const suppliedOrigin = request.headers.get("origin") ?? request.headers.get("referer");
  if (suppliedOrigin === null || suppliedOrigin === "null") {
    return authBoundaryError("Missing or null Origin", "MISSING_OR_NULL_ORIGIN");
  }
  try {
    if (new URL(suppliedOrigin).origin === browserOrigin) return undefined;
  } catch {
    // Invalid browser origins fail through the same public boundary as hostile origins.
  }
  return authBoundaryError("Invalid origin", "INVALID_ORIGIN");
}

function authBoundaryError(message: string, code: string): Response {
  return Response.json({ message, code }, { status: 403 });
}
