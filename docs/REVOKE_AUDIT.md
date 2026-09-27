# SCJWT revoke path audit (Better Auth 1.7.6)

SCJWT invalidation is database-backed. Every presented token resolves its `sid` against the canonical Better Auth session table before a signed native session cookie is injected into the endpoint request. A missing or expired row returns `401`; no separate JWT blocklist exists.

Audit target: Better Auth 1.7.6 session-deletion paths and the next SCJWT-backed request.

## Checklist

| Path | Better Auth API | Session-row effect | Next SCJWT request | Coverage |
|---|---|---|---|---|
| Sign out | `auth.api.signOut` | Deletes current row | `401` | Automated in `test/native-session.test.ts` |
| Revoke one session | `auth.api.revokeSession` | Deletes target row | `401` | Better Auth 1.7.6 source audit |
| Revoke other sessions | `auth.api.revokeOtherSessions` | Deletes other rows; keeps current | Revoked tokens `401` | Better Auth 1.7.6 source audit |
| Revoke all sessions | `auth.api.revokeSessions` | Deletes all user rows | `401` | Better Auth 1.7.6 source audit |
| Change password, default | `auth.api.changePassword` | Keeps existing sessions | Token remains valid to effective expiry | Better Auth 1.7.6 source audit |
| Change password with revoke | `revokeOtherSessions: true` | Deletes other rows | Revoked tokens `401` | Better Auth 1.7.6 source audit |
| Password reset | `auth.api.resetPassword` | Deletes rows only with `emailAndPassword.revokeSessionsOnPasswordReset: true` | `401` when configured | Better Auth 1.7.6 source audit |
| Delete user | `auth.api.deleteUser` | Deletes user sessions | `401` | Better Auth 1.7.6 source audit |
| Admin ban | `auth.api.banUser` | Deletes all target rows | `401` | Automated in `test/admin-revoke-paths.test.ts` |
| Admin revoke one | `auth.api.revokeUserSession` | Deletes target row | `401` | Automated in `test/admin-revoke-paths.test.ts` |
| Admin revoke all | `auth.api.revokeUserSessions` | Deletes all target rows | `401` | Automated in `test/admin-revoke-paths.test.ts` |
| Unban user | `auth.api.unbanUser` | Does not recreate sessions | Old tokens remain invalid | Source-audited; intentionally not treated as revival |
| Stop impersonating | `auth.api.stopImpersonating` | Deletes impersonation row and restores the admin cookie | Impersonation token `401` | Better Auth 1.7.6 source audit |
| Fingerprint mismatch | SCJWT before hook | Keeps row | Mismatched token `401`; correctly bound token remains valid | Automated in `test/fingerprint-mode.test.ts` |
| Custom-claim mismatch | SCJWT before hook | Keeps row | `401` | Automated in `test/custom-claims.test.ts` |

## Host configuration

- Set `emailAndPassword.revokeSessionsOnPasswordReset: true` when password reset must invalidate every device.
- Use `revokeOtherSessions: true` on password change when other devices must lose access immediately.
- A configured `secondaryStorage` must also set `session.storeSessionInDatabase: true`; SCJWT deliberately validates the immediately revocable database row.
- Header-placement clients must remove their locally stored Bearer token after logout or revocation. The server cannot clear client-managed authorization state.

## References

- `src/plugin/hooks.ts` — authoritative session lookup, native request-cookie injection, and fingerprint revocation.
- `test/native-session.test.ts` — native session transport and core sign-out invalidation.
- `test/admin-revoke-paths.test.ts` — Better Auth 1.7.6 admin ban and revoke paths.
- `test/fingerprint-mode.test.ts` — device/IP mismatch revocation.
- Better Auth test utilities: <https://better-auth.com/docs/plugins/test-utils>
