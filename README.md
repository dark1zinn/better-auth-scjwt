# better-auth-scjwt

Session-Centric JWT transport for [Better Auth](https://better-auth.com). The plugin replaces the client-visible session token with an HS256 JWT while keeping the Better Auth database session row authoritative. Deleting or expiring that row invalidates the JWT on its next use.

## Install

```bash
bun add better-auth-scjwt better-auth @better-auth/core jose
```

Supported peer ranges:

- `better-auth` and `@better-auth/core`: `^1.7.6`
- `jose`: `^6.2.12`

## Server setup

```ts
import { betterAuth } from "better-auth";
import { scjwt } from "better-auth-scjwt";

export const auth = betterAuth({
  database: yourAdapter,
  baseURL: "https://api.example.com",
  secret: process.env.BETTER_AUTH_SECRET,
  plugins: [scjwt()],
});
```

`scjwt()` uses Better Auth's resolved secret, authentication base URL, native session lifetime, cookies, and refresh policy. It does not require a second signing key or issuer.

A database is mandatory. When `secondaryStorage` is configured, set `session.storeSessionInDatabase: true` so the canonical row remains immediately revocable:

```ts
betterAuth({
  database: yourAdapter,
  secondaryStorage: yourSecondaryStore,
  session: { storeSessionInDatabase: true },
  plugins: [scjwt()],
});
```

Secondary-storage-only sessions fail during initialization.

## Client setup

```ts
import { createAuthClient } from "better-auth/client";
import { scjwtClient } from "better-auth-scjwt/client";

export const authClient = createAuthClient({
  baseURL: "https://api.example.com",
  plugins: [scjwtClient()],
});
```

The client plugin supplies Better Auth type inference. Import it from `better-auth-scjwt/client`; it is intentionally not re-exported by the server entrypoint.

## Options

```ts
interface ScjwtOptions {
  tokenPlacement?: "cookie" | "header";
  fingerprintMode?: "strict" | "ip-only";
  getCustomClaims?: (context: {
    session: Session;
    user: User;
    request: Request | undefined;
  }) => Awaitable<Record<string, JsonValue>>;
}
```

| Option | Default | Behavior |
|---|---|---|
| `tokenPlacement` | `"cookie"` | Selects the only accepted and emitted SCJWT transport. |
| `fingerprintMode` | `"strict"` | `strict` binds IP, User-Agent, and `Sec-CH-UA-Platform`; `ip-only` binds only IP. |
| `getCustomClaims` | unset | Resolves visible signed JSON claims at issuance, refresh, and verification. |

### Cookie placement

Cookie placement uses the resolved Better Auth session-cookie name and attributes, including `advanced.cookiePrefix`, custom cookie names, and the effective `__Secure-` prefix. The plugin replaces only a live native session-token `Set-Cookie` value with the SCJWT. Native session-data, account-data, and clearing cookies remain intact.

Send the cookie unchanged on subsequent Better Auth requests. The before hook verifies the SCJWT, resolves its backing row, signs the row's opaque `session.token` as a request-only Better Auth cookie, and lets the normal Better Auth endpoint or middleware consume it.

### Header placement

Header placement emits:

```http
set-auth-token: <SCJWT>
Access-Control-Expose-Headers: set-auth-token
```

Send the value back as:

```http
Authorization: Bearer <SCJWT>
```

Live native session-token, session-data, and `dontRemember` cookies are removed from successful issuance responses; account and clearing cookies are preserved. Header clients must remove their locally stored Bearer token after logout or revocation because a server cannot clear client-managed authorization state.

The configured placement is authoritative. Cookie mode ignores `Authorization`; header mode ignores the session cookie. This makes requests containing both transports deterministic.

## Native session lifecycle

SCJWT issuance follows `ctx.context.newSession`, not a path allowlist. It therefore covers credential sign-in/sign-up, social callbacks, passwordless plugins, passkeys, impersonation, and any plugin that uses Better Auth's `setSessionCookie`. Failed and non-2xx responses never receive a replacement SCJWT.

Better Auth owns refresh timing:

```ts
betterAuth({
  session: {
    expiresIn: 60 * 60 * 24 * 7,
    updateAge: 60 * 60 * 24,
  },
  plugins: [scjwt()],
});
```

When Better Auth refreshes a native session and sets `newSession`, SCJWT is reissued in the configured transport. There is no plugin-specific sliding-session threshold or competing database update.

Token expiration is capped to:

```txt
min(database session.expiresAt, issuedAt + Better Auth session.expiresIn)
```

## JWT payload and key rotation

The core payload is:

| Claim | Meaning |
|---|---|
| `iss` | Resolved Better Auth authentication base URL. |
| `sub` | `user:{session.userId}`. |
| `fp` | Lowercase SHA-256 fingerprint. |
| `iat`, `exp` | Unix issuance and effective-expiry seconds. |
| `sid` | Canonical Better Auth session-row ID. |

With a single Better Auth `secret`, SCJWT signs directly with that secret. With Better Auth `secrets`, new tokens carry the current secret version as `kid`; verification accepts current and retained versions.

Without `getCustomClaims`, every extra payload key is rejected. With a resolver, custom claims must:

- be a plain JSON object with at most 16 top-level keys;
- serialize to at most 1024 UTF-8 bytes;
- contain no values deeper than eight containers;
- contain only finite numbers, strings, booleans, null, arrays, and plain objects;
- not use `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `fp`, or `sid`.

The resolver runs again after the session and user are loaded. The presented custom claims must deep-equal the current result. An authorization-state change therefore rejects a stale token without deleting its session; a device-fingerprint mismatch deletes the backing session as a compromise response.

## IP and proxy configuration

SCJWT uses Better Auth 1.7's `getIP`. Configure proxy trust only through Better Auth:

```ts
betterAuth({
  advanced: {
    ipAddress: {
      ipAddressHeaders: ["x-forwarded-for"],
      trustedProxies: ["192.0.2.10", "10.0.0.0/24"],
      ipv6Subnet: 64,
    },
  },
  plugins: [scjwt()],
});
```

Do not trust forwarding headers from origins directly reachable by clients. `ip-only` relaxes browser-header binding; it does not disable IP binding.

## Security model

- Signature, issuer, expiry, payload shape, session subject, database expiry, fingerprint, and configured custom claims are checked before native session injection.
- Missing SCJWT falls through to ordinary Better Auth handling. A present invalid SCJWT returns Better Auth's standard `401 UNAUTHORIZED` response.
- Session deletion is immediate revocation; there is no SCJWT blocklist.
- Fingerprint mismatch calls `internalAdapter.deleteSession(session.token)` before returning `401`.
- Custom-claim mismatch returns `401` without deleting the session.
- Revocation audit: [`docs/REVOKE_AUDIT.md`](./docs/REVOKE_AUDIT.md).

## Migration from 0.0.x

1. Remove `jwtSecret`, `issuer`, `expiresInSeconds`, `cookieName`, and `slidingSession` from `scjwt()`.
2. Configure signing, issuer, lifetime, and refresh through Better Auth's `secret`/`secrets`, `baseURL`, and `session` options.
3. Replace any hard-coded `auth-token` cookie handling with Better Auth's resolved session-cookie name, normally `better-auth.session_token` or its secure-prefixed form.
4. If `secondaryStorage` is enabled, add `session.storeSessionInDatabase: true`.
5. Move client imports to `better-auth-scjwt/client` if they previously used the root package.
6. Header clients must expose/read `set-auth-token` and clear their stored Bearer token after logout.

This is a clean cutover; removed options and the old cookie name have no compatibility aliases.

## Development

```bash
bun install
bun test
bun run build
```

The integration suite exercises real Better Auth endpoints with the memory adapter and test-utils plugin.

## License

[MIT](./LICENSE)
