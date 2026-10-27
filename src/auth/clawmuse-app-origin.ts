const ACCOUNT_PATHS = new Set([
  "/api/auth/get-session",
  "/api/auth/sign-in/email",
  "/api/auth/sign-up/email",
  "/api/auth/sign-out",
  "/api/auth/delete-user",
  "/api/auth/clawmuse/devices",
  "/api/auth/clawmuse/devices/rename",
  "/api/auth/clawmuse/devices/remove",
]);

export function clawmuseAppOrigins(value: string | undefined): Set<string> {
  return new Set(
    (value ?? "https://app.clawmuse.com")
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean)
      .map((origin) => {
        const url = new URL(origin);
        if (url.origin !== origin) throw new Error(`invalid ClawMuse app origin: ${origin}`);
        return origin;
      }),
  );
}

/**
 * Lets the ClawMuse browser client use the same bearer account API as the native and desktop
 * apps. Cookies are dropped, so the only credential is the bearer token the page attaches itself;
 * with no ambient credential the Origin can be rewritten to the Hub's own, as the native clients do.
 */
export function handleClawMuseAppRequest(
  request: Request,
  appOrigins: ReadonlySet<string>,
  hubOrigin: string,
  handle: (request: Request) => Promise<Response>,
): Promise<Response> | undefined {
  const origin = request.headers.get("origin");
  if (origin === null || !appOrigins.has(origin)) return undefined;
  if (!ACCOUNT_PATHS.has(new URL(request.url).pathname)) return undefined;
  if (request.method === "OPTIONS") {
    return Promise.resolve(
      new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": origin,
          "access-control-allow-methods": "GET, POST",
          "access-control-allow-headers": "authorization, content-type",
          "access-control-max-age": "600",
          vary: "Origin",
        },
      }),
    );
  }
  const headers = new Headers(request.headers);
  for (const name of ["cookie", "referer", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"]) {
    headers.delete(name);
  }
  headers.set("origin", hubOrigin);
  const forwarded = new Request(request.url, {
    method: request.method,
    headers,
    ...(request.method === "GET" || request.method === "HEAD"
      ? {}
      : { body: request.body, duplex: "half" }),
  } as RequestInit);
  return handle(forwarded).then((response) => {
    const result = new Response(response.body, response);
    result.headers.delete("set-cookie");
    result.headers.set("access-control-allow-origin", origin);
    result.headers.set("access-control-expose-headers", "set-auth-token");
    result.headers.append("vary", "Origin");
    return result;
  });
}
