# SCJWT revoke path audit (Better Auth 1.7.18)

SCJWT invalidation is lifecycle-backed. Every presented token uses its `sid` to load the durable Better Auth session row, recovers that row's opaque native token, and asks Better Auth's `internalAdapter.findSession` whether the session is still live before a signed native session cookie is injected into the endpoint request. A missing row, a session that `findSession` no longer returns (including a secondary-store eviction of a preserved row), or an expired session returns `401`; no separate JWT blocklist exists.

Audit target: Better Auth 1.7.18 session-deletion paths and the next SCJWT-backed request. "Root" tests use the memory adapter (`bun test`); "Nest" tests are HTTP profiles in `examples/nestjs/test/e2e` (`bun run --cwd examples/nestjs test:e2e`).

## Checklist

| Path | Better Auth route | Session effect | Next SCJWT request | Coverage |
|---|---|---|---|---|
| Sign out | `/sign-out` | Deletes current session | `401` | Root `test/native-session.test.ts`; Nest `scjwt-only` |
| Revoke one session | `/revoke-session` | Deletes target session | `401` | Nest `scjwt-only` |
| Revoke other sessions | `/revoke-other-sessions` | Deletes others; keeps current | Revoked tokens `401` | Nest `scjwt-only` |
| Revoke all sessions | `/revoke-sessions` | Deletes all user sessions | `401` | Root `test/native-session.test.ts`; Nest `scjwt-only` |
| Change password, default | `/change-password` | Keeps existing sessions | Every token remains valid to its effective expiry | Root `test/refresh-policy.test.ts` |
| Change password with revoke | `revokeOtherSessions: true` | Deletes every session, including the presenting one, and issues a new session to the caller | Presented and other tokens `401`; replacement valid | Root `test/refresh-policy.test.ts`; Nest `scjwt-only` |
| Password reset (core) | `/request-password-reset` + `/reset-password` | Deletes sessions only with `emailAndPassword.revokeSessionsOnPasswordReset: true` | `401` when configured; unchanged otherwise | Root `test/native-session.test.ts` (configured), `test/refresh-policy.test.ts` (default) |
| Password reset (email OTP) | `/email-otp/reset-password` | Same setting as core reset | `401` when configured | Nest `email-otp`; `combined-plugins` (two sessions proven live via `/me` immediately before the reset, both `401` after) |
| Delete user (self) | `/delete-user` | Deletes user and sessions | `401` | Root `test/native-session.test.ts` |
| Admin ban | `/admin/ban-user` | Deletes all target sessions | `401` | Root `test/admin-revoke-paths.test.ts`; Nest `admin`, `combined-plugins` |
| Admin revoke one | `/admin/revoke-user-session` | Deletes target session | `401` | Root `test/admin-revoke-paths.test.ts`; Nest `admin`, `combined-plugins` |
| Admin revoke all | `/admin/revoke-user-sessions` | Deletes all target sessions | `401` | Root `test/admin-revoke-paths.test.ts`; Nest `admin` |
| Admin remove user | `/admin/remove-user` | Deletes user and sessions | `401` | Nest `admin` |
| Unban user | `/admin/unban-user` | Does not recreate sessions | Old tokens remain `401` | Nest `admin`, `combined-plugins` |
| Stop impersonating | `/admin/stop-impersonating` | Deletes impersonation session; restores admin session from `admin_session` | Impersonation token `401`; admin `sid` restored | Nest `admin`, `combined-plugins` |
| Secondary-store eviction | `secondaryStorage` entry removed, row preserved | `findSession` returns null | `401` | Root `test/secondary-storage.test.ts` |
| Session store outage | Session row or `secondaryStorage` read throws | No lookup result | `500`, no credential issued, no fallback to the other store; recovers when the store returns | Root `test/secondary-storage.test.ts` |
| Store resolves another session | `findSession(token)` returns a session whose `id` differs from `sid` | Treated as not live | `401` | Root `test/secondary-storage.test.ts` |
| Refresh racing revocation | `/get-session` refresh paused before its row update while the session is deleted | Better Auth's update finds no row | Racing request `401`; old and any replacement token `401` | Root `test/secondary-storage.test.ts` |
| Fingerprint mismatch | SCJWT before hook | Keeps session | Mismatched token `401`; bound token remains valid | Root `test/fingerprint-mode.test.ts` |
| Custom-claim mismatch | SCJWT before hook | Keeps session | `401` | Root `test/custom-claims.test.ts` |
| Cookie cache snapshot | `session.cookieCache` with a still-fresh `session_data` cookie | Snapshot removed from the SCJWT request; session and user read from the store | Revoked session `401`; live session returns current role and profile | Root `test/session-cache.test.ts`; Nest `rbac` (cookie-cache profile) |
| Email-OTP sign-in on unverified account | `/sign-in/email-otp` (`revokeUnprovenAccountAccess`) | Deletes pre-proof sessions and linked accounts, then marks email verified | Pre-proof tokens `401` | Nest `combined-plugins` |

Session refresh (`/get-session` past `updateAge`) and `/update-session` re-issue an SCJWT with the same `sid`; sign-out afterwards invalidates both the old and replacement tokens (root `test/native-session.test.ts`). `disableSessionRefresh`, the `disableRefresh` query, `deferSessionRefresh` (GET reads, POST refreshes), `rememberMe: false`, and `freshAge` keep their native semantics (root `test/refresh-policy.test.ts`, `test/session-lifetime.test.ts`).

A request that already passed SCJWT authentication before a revocation completes is not interrupted; revocation guarantees that every request evaluated after it rejects the old and any replacement token. No atomicity beyond Better Auth's own storage operations is implied.

## Host configuration

- Set `emailAndPassword.revokeSessionsOnPasswordReset: true` when password reset must invalidate every device.
- Use `revokeOtherSessions: true` on password change when other devices must lose access immediately.
- A configured `secondaryStorage` must also set `session.storeSessionInDatabase: true`; the row maps `sid` to the native token while `findSession` decides liveness.
- Header-placement clients must remove their locally stored Bearer token after logout or revocation. The server cannot clear client-managed authorization state.

## References

- `src/plugin/hooks.ts` — `resolveAuthoritativeSession`, native request-cookie injection, fingerprint and custom-claim rejection.
- `test/native-session.test.ts`, `test/secondary-storage.test.ts`, `test/admin-revoke-paths.test.ts`, `test/fingerprint-mode.test.ts`, `test/custom-claims.test.ts` — root lifecycle coverage.
- `examples/nestjs/test/e2e/*.e2e-spec.ts` — HTTP profiles per plugin and combined.
