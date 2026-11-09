# better-auth-scjwt

Session-Centric JWT transport for [Better Auth](https://better-auth.com). The plugin replaces the client-visible session token with an HS256 JWT while keeping the Better Auth database session row authoritative. Deleting or expiring that row invalidates the JWT on its next use.

## Install

```bash
bun add better-auth-scjwt better-auth @better-auth/core jose
```

Supported peer ranges:

- `better-auth` and `@better-auth/core`: `~1.7.18` (tested against 1.7.18; 1.8 is not yet supported)
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

### Plugin order

Register `scjwt()` before any plugin whose hooks read the current session:

```ts
plugins: [scjwt(), admin(), username(), emailOTP({ ... }), i18n({ ... })],
```

Better Auth runs user hooks first, then plugin before-hooks in registration order. SCJWT's before-hook is what turns the presented JWT into `ctx.context.session` and the request-only native cookie, so a later hook (for example username's `/update-user` ownership and `immutableUsername` checks) sees the authenticated session. Request interceptors such as captcha (`onRequest`) run before all hooks and are unaffected by order. Keep translation plugins such as i18n last among your plugins so their after-hook translates the final error.

Issuance does not depend on where `scjwt()` is registered. Its `init` appends an internal `scjwt-session-finalizer` plugin after all registered plugins, so the SCJWT is signed only after every plugin after-hook has run. A later hook that denies the request, withdraws the new session (for example a pending two-factor challenge), or replaces it decides the outcome. Requests fail with `[scjwt] session finalizer must run after all plugin after-hooks.` if another plugin's `init` appends after-hooks behind the finalizer, and `scjwt()` must be registered exactly once. Response interceptors (`onResponse`) that rewrite authentication headers after the hook pipeline are outside this guarantee.

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

Send the cookie unchanged on subsequent Better Auth requests. The before hook verifies the SCJWT, then resolves it in two stages: the signed `sid` locates the durable database row only to recover its opaque native `session.token`, and Better Auth's lifecycle-aware `internalAdapter.findSession(token)` decides whether that session is still live and returns the authoritative session and user. The hook signs the opaque token as a request-only Better Auth cookie and lets the normal Better Auth endpoint or middleware consume it.

With `secondaryStorage`, `findSession` consults the secondary store first. A session that the secondary store no longer holds is rejected even when `session.preserveSessionInDatabase: true` keeps an unexpired database row for auditing, so evicting or revoking the secondary-store entry revokes the SCJWT.

### Cookie cache

Better Auth's `session.cookieCache` stores a signed `session_data` snapshot in the browser so `getSession` can skip the session store until the snapshot expires. Under SCJWT the snapshot is never the server-side source of truth: for every request with a verified SCJWT, the before hook removes `session_data` (and its chunks) from the request it hands to Better Auth, so `/get-session`, guards built on `auth.api.getSession` such as `@thallesp/nestjs-better-auth`, and other endpoints read the current session and user from the store. Role downgrades, profile changes, and session-field updates therefore take effect on the next request instead of after `cookieCache.maxAge`. Better Auth may still emit `session_data` in responses, and client-side code that reads it (for example a UI session store) can show older data until it refreshes; server authorization is unaffected. A revoked session is rejected before any endpoint runs, with or without a snapshot.

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

SCJWT issuance follows `ctx.context.newSession`, not a path allowlist. It therefore covers credential sign-in/sign-up, social callbacks, passwordless plugins, passkeys, impersonation, and any plugin that uses Better Auth's `setSessionCookie`, including redirects (`ctx.redirect` or a returned 3xx `Response`, whose status and `Location` are preserved). Results with status 400 or higher, whether thrown API errors or returned `Response` objects, never receive a replacement SCJWT and expire native session cookies when the request established a new session. Unrelated failures that did not establish a session leave existing cookies intact.

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
| `remember` | `false` when Better Auth created the session with `rememberMe: false`; otherwise `true`. |

`remember` carries Better Auth's non-persistent session policy without a client cookie. At issuance it mirrors the native `dontRemember` marker that `setSessionCookie` writes; on each request SCJWT discards any caller-supplied `dontRemember` cookie and reconstructs the signed marker only when `remember` is `false`. Better Auth then skips refresh exactly as it would for a native `rememberMe: false` session, so such sessions keep their one-day lifetime in both placements, and replacement tokens (for example from `/update-session`) inherit the policy. In cookie placement the SCJWT cookie of a non-persistent session is a browser-session cookie; header clients decide how long they keep their own Bearer token.

With a single Better Auth `secret`, SCJWT signs directly with that secret. With Better Auth `secrets`, new tokens carry the current secret version as `kid`; verification accepts current and retained versions.

Without `getCustomClaims`, every extra payload key is rejected. With a resolver, custom claims must:

- be a plain JSON object with at most 16 top-level keys;
- serialize to at most 1024 UTF-8 bytes;
- contain no values deeper than eight containers;
- contain only finite numbers, strings, booleans, null, arrays, and plain objects;
- not use `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `fp`, `sid`, or `remember`.

The resolver runs again after the session and user are loaded. Presented custom claims must equal the current result under JSON semantics: the comparison is structural, object key order is ignored, and numbers compare by value, so values that JSON normalizes (for example `-0`, which serializes as `0`) still match. Custom-claim and device-fingerprint mismatches reject the token without deleting its shared backing session. A resolver that returns invalid claims at issuance fails the request without delivering a token.

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

- Signature, issuer, expiry, payload shape, session subject, lifecycle-aware session liveness (`internalAdapter.findSession`), database expiry, fingerprint, and configured custom claims are checked before native session injection.
- Missing SCJWT falls through to ordinary Better Auth handling. A present invalid SCJWT returns Better Auth's standard `401 UNAUTHORIZED` response.
- Session deletion is immediate revocation; there is no SCJWT blocklist.
- Fingerprint mismatch returns `401` without deleting the session, preventing a mismatched bearer from terminating the shared session.
- Custom-claim mismatch returns `401` without deleting the session.
- Revocation audit: [`docs/REVOKE_AUDIT.md`](./docs/REVOKE_AUDIT.md).

## Migration

### Tokens issued before the `remember` claim

`remember` is a required claim. Tokens issued by earlier 0.1.x builds lack it and are rejected with `401`; users sign in again to receive a replacement. No database migration is involved, and there is no fallback that accepts the old shape.

### From 0.0.x

1. Remove `jwtSecret`, `issuer`, `expiresInSeconds`, `cookieName`, and `slidingSession` from `scjwt()`.
2. Configure signing, issuer, lifetime, and refresh through Better Auth's `secret`/`secrets`, `baseURL`, and `session` options.
3. Replace any hard-coded `auth-token` cookie handling with Better Auth's resolved session-cookie name, normally `better-auth.session_token` or its secure-prefixed form.
4. If `secondaryStorage` is enabled, add `session.storeSessionInDatabase: true`.
5. Move client imports to `better-auth-scjwt/client` if they previously used the root package.
6. Header clients must expose/read `set-auth-token` and clear their stored Bearer token after logout.

This is a clean cutover; removed options and the old cookie name have no compatibility aliases.

## Development

Tested toolchain: Bun 1.4.2 and Node.js 24 (>= 24.11.0). Bun runs the tests, build, and the NestJS example; Node.js is required by Node-based tooling and by the packed-consumer checks. `nix develop` (or `direnv allow`) provides both from `flake.nix`.

```bash
bun install
bun test
bun run build
```

The root integration suite exercises real Better Auth endpoints with the memory adapter and test-utils plugin. The NestJS example adds isolated HTTP profiles for SCJWT alone, Admin, Admin RBAC, i18n, captcha, username, email OTP, and all of them combined; see [`examples/README.md`](./examples/README.md).

## License

[MIT](./LICENSE)
