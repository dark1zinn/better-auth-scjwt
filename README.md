# better-auth-scjwt

Session-Centric JWT (SCJWT) plugin for [Better Auth](https://better-auth.com). It issues a signed, device-fingerprinted JWT that points at a database session row. The database remains the source of truth; the JWT is a tamper-proof pointer with a bounded lifetime.

See why in [the docs](./docs)

## Install

```bash
bun add better-auth-scjwt
# peer dependencies (if not already installed)
bun add better-auth jose
```

**Peer dependencies:** `better-auth` `>=1.0.0`, `jose` `>=5.0.0`

## Quick start

### Server

```ts
import { betterAuth } from "better-auth";
import { scjwt } from "better-auth-scjwt";

export const auth = betterAuth({
  // database adapter required — sessions are stored in DB
  database: /* your adapter */,
  plugins: [
    scjwt({
      jwtSecret: process.env.JWT_SECRET!,
      issuer: "https://api.example.com",
    }),
  ],
});
```

After a successful `/sign-in/*` or `/sign-up/*` flow, the plugin:

1. Signs an HS256 JWT bound to the new session row
2. Strips native Better Auth session cookies from the response
3. Delivers the JWT via cookie (default) or response header

### Client

```ts
import { createAuthClient } from "better-auth/client";
import { scjwtClient } from "better-auth-scjwt/client";

export const authClient = createAuthClient({
  baseURL: "https://api.example.com",
  plugins: [scjwtClient()],
});
```

The client plugin provides `$InferServerPlugin` type inference only. Token refresh is handled server-side (see [Sliding session](#sliding-session)).

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `jwtSecret` | `string` | — | **Required.** HS256 signing key |
| `issuer` | `string` | — | **Required.** Issuer URL (`iss` claim) |
| `expiresInSeconds` | `number` | `3600` | JWT and session validity window (seconds) |
| `cookieName` | `string` | `"auth-token"` | HTTP-only cookie name when `tokenPlacement` is `"cookie"` |
| `tokenPlacement` | `"cookie"` \| `"header"` | `"cookie"` | How the JWT is delivered and read |
| `slidingSession` | `boolean` | `false` | Re-sign JWT for active users before expiry (see below) |

### Token placement

**`cookie` (default)** — JWT is set as an HTTP-only cookie (`auth-token` by default). The gateway reads it from the `Cookie` header on each request.

**`header`** — JWT is returned in the `set-auth-token` response header on issuance/refresh. Clients send it back via `Authorization: Bearer <token>`.

## Sliding session

Sliding refresh is **disabled by default** (`slidingSession: false`). When disabled, sessions end at JWT `exp` or when the database row is revoked—whichever applies first.

Enable it to keep actively used sessions alive:

```ts
scjwt({
  jwtSecret: process.env.JWT_SECRET!,
  issuer: "https://api.example.com",
  slidingSession: true,
})
```

When enabled, requests within the last **20%** of the token lifetime trigger:

1. Extension of the database session `expiresAt`
2. Re-signing of the JWT
3. Delivery of the new token on the response (`onResponse`)

Better Auth's built-in `session.updateAge` refresh does **not** update SCJWT tokens. If you use `slidingSession: true`, disable the native session refresh to avoid conflicting behavior:

```ts
betterAuth({
  session: {
    disableSessionRefresh: true,
  },
  plugins: [scjwt({ /* ... */, slidingSession: true })],
});
```

## JWT payload

Strict v1 payload (no extra claims):

| Claim | Description |
|-------|-------------|
| `iss` | Issuer URL from plugin options |
| `sub` | `user:{userId}` |
| `fp` | SHA-256 hex fingerprint of `{ ip, ua, platform }` |
| `iat` / `exp` | Issued-at and expiry (Unix seconds) |
| `sid` | Database session row primary key |

## Security model

- **Database as source of truth** — Revoking or deleting the session row invalidates the JWT immediately on the next request.
- **Device binding** — Each token embeds a fingerprint (`fp`) derived from client IP, User-Agent, and `Sec-CH-UA-Platform`. A mismatch is treated as compromise: the session row is deleted and the request returns `401`.
- **Fail-closed** — Invalid, expired, or mismatched tokens reject the request; missing tokens fall through to standard Better Auth handling.
- **Opaque payload** — No user profile data in the JWT; only the session pointer and fingerprint.

## Development

```bash
bun install
bun test
bun run build
```

Tests live in `test/` at the project root. Integration tests use Better Auth's [test-utils plugin](https://better-auth.com/docs/plugins/test-utils) via a test-only auth instance.

## Compatibility notes

- **Issuance paths:** JWT delivery hooks run after `/sign-in/*` and `/sign-up/*`. OAuth, magic-link, and other session-creating flows are not covered yet.
- **Sign-out:** JWT cookies/headers are not cleared on sign-out yet; plan to address in a future release.
- **Reverse proxies:** Fingerprint uses the request IP as seen by Better Auth (`getIp`). Clients behind proxies may need consistent IP extraction configuration.

## License

[MIT](./LICENCE)
