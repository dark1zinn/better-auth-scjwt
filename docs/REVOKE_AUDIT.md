# SCJWT revoke path audit (Better Auth v1.6.14)

SCJWT invalidation is **database-backed**: when the session row referenced by JWT claim `sid` is deleted, the next `onRequest` call returns `401` with `"Session not found."` There is no separate server-side JWT blocklist.

Audit target: confirm Better Auth revocation flows remove the session row (or document when they do not).

## Checklist

| Path | API / endpoint | Session row effect | SCJWT after revoke | Automated test | Notes |
|------|----------------|-------------------|-------------------|----------------|-------|
| Sign out | `auth.api.signOut` / `POST /sign-out` | DELETE current row | Dead (`401`) | Yes | Client cookie may remain until patch-02 |
| Revoke one session | `auth.api.revokeSession` / `POST /revoke-session` | DELETE target row | Dead (`401`) | Yes | Body: `{ token }` |
| Revoke other sessions | `auth.api.revokeOtherSessions` / `POST /revoke-other-sessions` | DELETE other rows | Other JWTs dead | Yes | Current session kept |
| Revoke all sessions | `auth.api.revokeSessions` / `POST /revoke-sessions` | DELETE all user rows | Dead (`401`) | Stretch | Includes current session |
| Change password (default) | `auth.api.changePassword` | **No change** | **Still valid until `exp`** | Yes (negative) | Host must pass `revokeOtherSessions: true` to kill other devices |
| Change password + revoke | `auth.api.changePassword` + `revokeOtherSessions: true` | DELETE all + new row | Old JWTs dead | Yes | New session token returned |
| Reset password | `auth.api.resetPassword` | DELETE all **if** `emailAndPassword.revokeSessionsOnPasswordReset: true` | Dead when configured | No | Host-config dependent |
| Delete user | `auth.api.deleteUser` | DELETE all user sessions | Dead (`401`) | Stretch | Requires `user.deleteUser.enabled` |
| Ban user | `auth.api.banUser` (admin plugin) | DELETE all target sessions | Dead (`401`) | Follow-up issue | Requires `admin()` plugin |
| Unban user | `auth.api.unbanUser` (admin plugin) | No session restore | N/A (sessions already gone) | Follow-up issue | Does not recreate sessions |
| Stop impersonating | `auth.api.stopImpersonating` (admin plugin) | DELETE impersonation row | Dead (`401`) | Follow-up issue | Admin session restored via cookie |
| Admin revoke session | `auth.api.revokeUserSession` (admin plugin) | DELETE target row | Dead (`401`) | Follow-up issue | Admin-gated |
| Admin revoke all | `auth.api.revokeUserSessions` (admin plugin) | DELETE all target rows | Dead (`401`) | Follow-up issue | Admin-gated |
| Fingerprint mismatch | SCJWT `onRequest` | DELETE compromised row | Dead (`401`) | Yes (`on-request.test.ts`) | Plugin-initiated revoke |

## Host configuration recommendations

- **`changePassword`**: pass `revokeOtherSessions: true` when changing password if other devices should lose SCJWT access immediately.
- **`emailAndPassword.revokeSessionsOnPasswordReset`**: set `true` if password reset should invalidate all sessions.
- **Sign-out**: gateway rejects revoked JWTs even though the client cookie is not cleared yet ([issue #2](https://github.com/dark1zinn/better-auth-scjwt/issues/2) tracks cookie clearing).

## Admin plugin follow-up

Automated tests for admin-plugin paths are tracked in [#8](https://github.com/dark1zinn/better-auth-scjwt/issues/8). See checklist rows marked "Follow-up issue".

## References

- [`src/plugin/session-bridge.ts`](../src/plugin/session-bridge.ts) — `loadSessionIntoContext`
- [`test/revoke-paths.test.ts`](../test/revoke-paths.test.ts) — core path integration tests
- [Better Auth test-utils](https://better-auth.com/docs/plugins/test-utils)
