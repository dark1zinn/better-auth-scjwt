# better-auth-scjwt technical specification

This document records the implemented native-session design, tested against Better Auth 1.7.18 (peer range `~1.7.18`). The package exposes `better-auth-scjwt` for the server plugin and `better-auth-scjwt/client` for client-side type inference.

## Invariants

1. **Lifecycle authority:** `sid` identifies a Better Auth database session row. Every presented SCJWT must resolve that row and then pass Better Auth's lifecycle-aware `internalAdapter.findSession` before authentication succeeds.
2. **Immediate revocation:** a deleted or expired row makes the next SCJWT request unauthorized.
3. **Native compatibility:** verified requests are converted into a correctly signed Better Auth session cookie and continue through the standard endpoint pipeline.
4. **Single configuration source:** Better Auth owns secrets, issuer/base URL, session lifetime, refresh timing, cookie settings, and proxy/IP resolution.
5. **Deterministic transport:** exactly one configured source is read. Cookie and header values never silently override each other.
6. **Fail closed:** a present invalid SCJWT returns Better Auth `UNAUTHORIZED`; a missing token falls through.

## Public API

```ts
export interface ScjwtOptions {
  tokenPlacement?: "cookie" | "header";
  fingerprintMode?: "strict" | "ip-only";
  getCustomClaims?: (
    context: ScjwtClaimContext,
  ) => Awaitable<Record<string, JsonValue>>;
}

export function scjwt(options?: ScjwtOptions): BetterAuthPlugin;
```

Defaults are cookie placement and strict fingerprinting. There are no plugin-local secret, issuer, lifetime, cookie-name, or sliding-refresh options.

## Initialization

`init` rejects missing database configuration. It also rejects `secondaryStorage` unless `session.storeSessionInDatabase` is `true`. The durable row is what maps a public `sid` to the opaque native token; `internalAdapter.findSession` then applies secondary-storage liveness, revocation, and `preserveSessionInDatabase` semantics.

The plugin is registered in `@better-auth/core`'s `BetterAuthPluginRegistry` and publishes the user options on the plugin object.

## Before hook

For every endpoint:

1. Read the SCJWT from the selected Better Auth session cookie or Bearer header.
2. Verify HS256, optional versioned-secret `kid`, issuer, `exp`, core payload shape, and custom JSON shape.
3. Load the row by `sid` only to recover its opaque native `session.token`, then call `internalAdapter.findSession(token)`. Reject when the row is missing, `findSession` returns null (for example, the secondary store dropped a preserved row's session), or the resolved session id differs from `sid`.
4. Using the authoritative session and user, reject an expired session, subject mismatch, or token lifetime beyond Better Auth's effective session limit.
5. Recompute the selected fingerprint. Reject a mismatch with `401` without deleting the shared backing session, so a mismatched bearer cannot terminate a legitimate device's session.
6. If configured, rerun `getCustomClaims` against the authoritative session/user and require exact JSON equality; do not delete the row on authorization-state mismatch.
7. Serialize the opaque `session.token` using Better Call's signed-cookie serializer and inject it under `ctx.context.authCookies.sessionToken.name` with Better Auth's `setRequestCookie`.
8. Populate `ctx.context.session` and continue the native pipeline.

## Strategy seam: plugin hooks and `newSession`

SCJWT is a universal `hooks.before[]`/`hooks.after[]` plugin with `matcher: () => true`, not an endpoint allowlist. Better Auth 1.7.18's public `BetterAuthPlugin` contract still models plugin hooks as these arrays, every session-establishing path (core credentials, social callbacks, passwordless plugins, impersonation, refresh, `update-session`) funnels through `setSessionCookie`, which sets `ctx.context.newSession`, and Better Auth's own bearer plugin uses the same signed request-cookie bridge. Registering `scjwt()` first makes its before-hook populate the session ahead of other plugins' session-dependent hooks.

## After hook

For every successful endpoint with `ctx.context.newSession`:

1. Derive the fingerprint from Better Auth `getIP` plus the configured browser inputs.
2. Resolve and validate custom claims.
3. Set `iat` and cap `exp` to `min(session.expiresAt, iat + sessionConfig.expiresIn)`.
4. Sign with Better Auth's current secret material.
5. Replace the live native session-token cookie or emit `set-auth-token`, according to placement.

Returned API errors and non-2xx `Response` values do not receive a replacement token. Better Auth `session.updateAge` is the only refresh policy.

## Token schema

Required claims:

```json
{
  "iss": "<resolved Better Auth auth base URL>",
  "sub": "user:<user id>",
  "fp": "<64 lowercase SHA-256 hex characters>",
  "iat": 0,
  "exp": 0,
  "sid": "<session row id>"
}
```

Optional resolver claims are limited to 16 top-level keys, 1024 UTF-8 JSON bytes, and eight nested containers. Registered JWT names and `fp`/`sid` are reserved. Non-finite numbers, non-JSON primitives, cycles, and class instances are rejected.

## Secret handling

- `secretConfig: string`: sign and verify directly; reject unexpected `kid`.
- Versioned `SecretConfig`: sign with `currentVersion`, include it as `kid`, and verify only a matching retained map entry.
- Algorithm: HS256 only.

## Response cookies

Cookie processing uses Better Auth's public `parseSetCookieHeader`, `splitSetCookieHeader`, `toCookieOptions`, and `setRequestCookie` helpers plus Better Call serialization. It does not maintain a competing cookie-name or prefix implementation.

Cookie placement retains native cache/account cookies. Header placement removes live session/session-data/`dontRemember` cookies, retains account and clearing cookies, and adds `set-auth-token` once to `Access-Control-Expose-Headers`.

## Runtime compatibility

Fingerprint hashing uses `globalThis.crypto.subtle.digest`. Runtime code has no `node:crypto` dependency and remains compatible with Fetch-based Node, Bun, Deno, Worker, and framework adapter environments supported by Better Auth.

## Verification gates

```bash
bun install
bun test test/native-session.test.ts
bun test test/custom-claims.test.ts
bun test test/fingerprint-mode.test.ts
bun test test/secondary-storage.test.ts
bun test test/admin-revoke-paths.test.ts
bun test
bun run build
```

The build must emit declarations for both package entrypoints. The test suite must prove native `getSession`, cookie/header delivery, effective expiry, callback issuance, refresh and `update-session` re-issuance with a stable `sid`, 2xx-only replacement, dynamic claims, fingerprint rejection without session deletion, storage invariants including secondary-store eviction of a preserved row, and admin revocation. The NestJS example's `test:e2e` profiles prove the same contract over HTTP with Admin, Admin RBAC, i18n, captcha, username, email OTP, and their combination.
