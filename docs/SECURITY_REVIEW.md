# Security and lifecycle review (Better Auth 1.7.18)

This review covers `better-auth-scjwt` as a replacement for Better Auth's native session transport: token cryptography, the Better Auth hook and session lifecycle, revocation, transport and CSRF boundaries, fingerprints, packaging, and the development and CI setup. Each finding below was reproduced against real Better Auth endpoints (memory adapter, `auth.handler` or `auth.api`) or read from the installed 1.7.18 source before it was changed, and each fix or coverage gap landed as its own conventional commit with its tests and documentation.

Baseline: `975c1c4` (merged to `main` as `b8a09c8`). Target: `better-auth`/`@better-auth/core` 1.7.18, `jose` 6.2.12, Bun 1.4.2, Node.js 24.

## Sources

- Better Auth [changelog](https://better-auth.com/changelog) (1.7.16–1.7.18 session-revocation and plugin fixes), [plugin hooks](https://better-auth.com/docs/concepts/plugins), [session management](https://better-auth.com/docs/concepts/session-management) (cookie cache, refresh, freshness), and [security reference](https://better-auth.com/docs/reference/security) (origin/CSRF, proxies, direct `auth.api` calls).
- Better Auth [security advisories](https://github.com/better-auth/better-auth/security/advisories). The advisories reviewed (for example [GHSA-fvxx-76fc-893x](https://github.com/better-auth/better-auth/security/advisories/GHSA-fvxx-76fc-893x) on revocation with secondary storage or cookie cache, [GHSA-2f9c-7xj7-gh55](https://github.com/better-auth/better-auth/security/advisories/GHSA-2f9c-7xj7-gh55) on email OTP, and [GHSA-4wq4-2ppv-q3hg](https://github.com/better-auth/better-auth/security/advisories/GHSA-4wq4-2ppv-q3hg) on the Expo signing oracle) are fixed at or before 1.7.16, below the supported `~1.7.18`. They are upstream issues, not SCJWT findings, and this review is not a transitive-dependency vulnerability scan.
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) (JWT best current practices), [MDN `Set-Cookie`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie) / RFC 6265 (`Max-Age` precedence), [tsdown declaration files](https://tsdown.dev/options/dts), and the [`auth@1.7.18`](https://registry.npmjs.org/auth/1.7.18) CLI release.
- Installed Better Auth 1.7.18 source: `api/dispatch.mjs` (hook order), `context/helpers.mjs` (plugin `init`), `api/routes/session.mjs` (cookie cache, refresh), `cookies/index.mjs` (`setSessionCookie`, `dontRemember`), `plugins/two-factor` (challenge flow), `@better-auth/core/utils/ip` (`getIP`), and `api/middlewares/origin-check.mjs`.

## Findings

Severity reflects impact on authentication under the stated condition, not general code quality.

| # | Finding | Condition | Severity | Status | Commit |
|---|---|---|---|---|---|
| 1 | A later plugin's after-hook could reject or replace a sign-in after SCJWT had already issued a token. Reproduced: a sign-up returned `403` with a `set-auth-token` that authenticated (`200`). A pending two-factor challenge in header placement also carried a token for the deleted credential session. | Any plugin with after-hooks registered after `scjwt()` | High (conditional) | Fixed: an internal `scjwt-session-finalizer` appended by `init` issues after all plugin after-hooks; failures, expired sessions, and signing errors clear the native transport; misordered or duplicate registration fails loudly | `60ff3e8` |
| 2 | A returned 3xx `Response` was treated as a failure (`!response.ok`), so the session cookies were cleared instead of issuing an SCJWT | Endpoints that return a raw redirect after `setSessionCookie` | Medium | Fixed: only status ≥ 400 counts as failure | `900f69e` |
| 3 | `rememberMe: false` sessions slid to the full `expiresIn` in header placement: the first `/get-session` extended a 24-hour session to 168 hours, because the `dontRemember` marker never reached the client | Header placement; cookie clients that drop the marker | Medium | Fixed: required signed `remember` claim; the before-hook reconstructs the marker from the claim and ignores caller-supplied markers. Breaking: older tokens are rejected | `5049d42` |
| 4 | With `session.cookieCache`, `/get-session` and guards built on `auth.api.getSession` returned the client's `session_data` snapshot, overriding the session and user SCJWT had just loaded. A role downgrade stayed visible as the old role until the snapshot expired. Revocation was not affected | `session.cookieCache.enabled` | Medium | Fixed: `session_data` and its chunks are removed from SCJWT-authenticated requests | `c85f12a` |
| 5 | Custom claims containing `-0` never verified: JSON serializes `-0` as `0`, and the comparison used `Object.is` | Resolvers returning `-0` | Low | Fixed: JSON numeric equality | `f641000` |
| 6 | Cookie liveness ignored `Max-Age` precedence: a negative `Max-Age` counted as live and a positive `Max-Age` with a past `Expires` as cleared, which could drop a clearing instruction, keep a live native cookie in header placement, or misread the `dontRemember` marker | Responses carrying those attribute combinations | Low | Fixed per RFC 6265 | `4260632` |
| 7 | The combined profile "proved" password-reset revocation with a token the preceding ban had already revoked | Test suite | Test gap | Fixed: two live sessions proven before the reset; disabling revocation makes the test fail | `9381a27` |
| 8 | Combined-profile cases depended on accounts and tokens from earlier cases | Test suite | Test gap | Fixed: each case is self-contained; verified alone and under shuffled order | `dd88a54` |
| 9 | JWT rejection boundaries (tampering, foreign keys and issuers, `alg: none`, HS384, missing or mistyped claims, expiry caps, `kid` handling) were not covered at the endpoint level | Test suite | Test gap | Covered with independently forged tokens; every rejection is the same generic `401` and the valid session survives | `fd5991c` |
| 10 | Transport and origin boundaries were not covered; Better Auth disables its origin check when `NODE_ENV` is `test`, so no existing test exercised it | Test suite | Test gap | Covered with `disableOriginCheck: false`; documented | `dd4186b` |
| 11 | Refresh policies, password-change defaults, storage outages, and refresh/revocation races were covered only by source reading | Test suite | Test gap | Covered; outages fail closed with `500` and no credential | `9f1c331` |
| 12 | Two-factor transitions were not exercised | Test suite | Test gap | Covered (OTP method) in a Nest profile and a root header-placement test | `90390ae` |
| 13 | `prepare` overlaid `tsc` declarations on tsdown's bundle, publishing extensionless `./plugin/*` re-exports. Packed and checked under `NodeNext`: `TS2834`, `scjwt` typed as `any`, Nest `UserSession` as `unknown` | Consumers using `NodeNext`, packages built through `prepare` | Medium (types) | Fixed: one tsdown declaration pipeline; `test:package` checks the packed tarball under Node.js, Bun, `bundler`, and `NodeNext` | `0db05f9` |
| 14 | `prepare` re-ran `bun install`, rebuilt, and could delete `node_modules` on every install, pack, and example refresh | Every install | Low (reliability) | Fixed: `prepack` builds; the example refresh uses `--frozen-lockfile --ignore-scripts` | `76e8bf5` |
| 15 | The example migrated with `auth@latest` | Example | Low (reproducibility) | Fixed: `auth` 1.7.18 locked as a dev dependency | `5cc3600` |
| 16 | Root tests were not type-checked; doing so exposed a transport test that signed a token from an unrelated empty database and so proved nothing | Test suite | Test gap | Fixed: `tsconfig.test.json`, `typecheck` scripts, checked row access | `b7237a1` |
| 17 | No CI | Repository | Process | Fixed: pinned, read-only workflow running the commands above per job and per E2E profile | `74a8839` |
| 18 | The development shell lacked Node.js, required by Node-based tooling and the packed-consumer check | Development | Low | Fixed: `nodejs_24` in the flake | `cec0a18` |
| 19 | With Better Auth's `bearer()` registered next to `scjwt()` in cookie placement, the native session token from a sign-up or sign-in response body authenticated as `Authorization: Bearer` (`200` with the user), because `bearer()` turns it into a native session cookie that SCJWT never sees, skipping fingerprint and custom-claim checks. Header placement rejected it (`401`) | `bearer()` registered alongside `scjwt()` | High (conditional) | Fixed: initialization fails when `bearer()` is registered, in either order; header placement replaces it. Breaking for such configurations | `23bafff` |
| 20 | `bearer()` appended by another plugin's `init` only appears in the resolved plugin list, so the startup check missed it | A plugin whose `init` installs `bearer()` | High (conditional) | Fixed: the per-request plugin-list check also rejects `bearer()` | `324468c` |
| 21 | A request that only refreshed the presented session and then failed expired the client's still-valid SCJWT; a session withdrawn by a later hook (`setNewSession(null)`) left a live native cookie that overwrote the SCJWT (cookie placement) or leaked a native credential (header placement) | Later hooks denying a refresh or withdrawing a session | Medium | Fixed: refresh-only failures and withdrawals drop the pending native cookies without clearing the client's SCJWT; failures that created a new session still expire it | `98459d6` |
| 22 | `rememberMe: false` tokens were capped at `session.expiresIn`, although Better Auth gives those sessions a fixed one-day lifetime and never refreshes them, so a shorter `expiresIn` logged users out early | `session.expiresIn` below one day | Medium | Fixed: issuance and verification cap non-persistent tokens at one day | `9140e9d` |
| 23 | The tampered-signature test changed only the final base64url character, whose low bits are unused for a 32-byte HMAC, so it failed intermittently | Test suite | Test gap | Fixed: the test flips a significant character | `2b3305b` |
| 24 | `auth:migrate` and `start:dev` in the example could load a missing or stale `dist` because installing no longer builds | Example | Low | Fixed: `preauth:migrate` and `prestart:dev` run `sync:scjwt` | `ee648e2` |

## Reviewed and not treated as defects

- **Revocation with cookie cache.** The before-hook resolves the session through `internalAdapter.findSession` before any endpoint runs, so a revoked session is rejected even with a fresh `session_data` cookie. Covered in `test/session-cache.test.ts`.
- **Token cryptography.** HS256 is pinned, the issuer is checked, `kid` only selects a configured Better Auth secret version (no trial decryption, no remote keys), claims are validated as finite JSON with prototype-safe accumulation, and the `sid`/subject/expiry/fingerprint checks run against the store. No signature, algorithm-confusion, key-selection, or prototype-pollution bypass was found. Adding `aud`/`typ` requirements was considered and not adopted: SCJWTs are only accepted by the instance whose secret and issuer signed them, and no cross-token confusion path was demonstrated.
- **Native `token` fields in response bodies.** Better Auth sign-up, sign-in, two-factor verification, and admin session listings return the opaque native session token in JSON. SCJWT does not rewrite these bodies because Better Auth's revoke endpoints consume them. That token does not authenticate: in cookie placement it is rejected as a cookie (`401`) and ignored as a Bearer value (`200` with a `null` session); in header placement it is ignored as a cookie and rejected as a Bearer value (`401`). The one plugin that would have accepted it, `bearer()`, is now refused (finding 19). It is still a session secret: treat these responses accordingly.
- **Fingerprint strength.** User-Agent and `Sec-CH-UA-Platform` are client-supplied and the IP depends on proxy configuration. When no IP resolves, `strict` binds only browser headers and `ip-only` binds nothing. This was kept for compatibility with server-to-server and IP-less deployments and is documented and tested rather than changed.
- **Header placement and CSRF.** Bearer tokens are not ambient, so Better Auth does not origin-check them; CORS governs which origins can send `Authorization` or read `set-auth-token`.
- **`onResponse` finalization.** Moving issuance to `onResponse` would order it after every hook but skip direct `auth.api` calls, so the `init`-appended finalizer was chosen instead.

## Remaining boundaries and limitations

- The finalizer's position relies on Better Auth 1.7.18 appending `init`-returned plugins and running plugin after-hooks in order. A plugin that appends after-hooks behind it fails requests with a configuration error instead of issuing early. `onResponse` interceptors that rewrite authentication headers after the hook pipeline are outside this guarantee. Re-check this when upgrading Better Auth.
- A request that passed authentication before a revocation completed is not interrupted; every request evaluated afterwards is rejected. Nothing beyond Better Auth's own storage atomicity is implied.
- Two-factor coverage is limited to the OTP method; TOTP, backup codes, trusted devices, passkeys, and provider MFA are not exercised.
- Direct `auth.api` calls bypass Better Auth's HTTP origin and CSRF checks; applications that forward browser headers must validate `Origin` themselves.
- Each request costs a durable-row lookup plus Better Auth's `findSession` read. This is what makes revocation immediate and should not be optimized away without measurements.
- CI has been validated by running every workflow command locally in a clean worktree and by `actionlint`; its first hosted run, and making the `CI` check required in branch protection, are pending repository-owner action.

## Verification

Results from the final branch state:

| Check | Result |
|---|---|
| `bun run typecheck` (src; src + test + scripts) | pass |
| `bun test` | 121 tests across 11 files pass |
| `bun run test:package` | Node.js 24.20.0 and Bun 1.4.2 runtime imports pass; `bundler` and `NodeNext` consumer type checks pass with `skipLibCheck` off; 14 packed files verified |
| `bun run --cwd examples/nestjs typecheck` / `test` / `build` | pass / 1 test pass / pass |
| `bun run --cwd examples/nestjs test:e2e` | 9 profiles, 51 tests pass |
| Production smoke (`auth:migrate` twice on a fresh database, `start:prod`) | sign-up issued an SCJWT, `/me` `200`, hostile-origin sign-out `403`, sign-out `200`, replay `401`, `rememberMe: false` kept its 24-hour expiry without re-issue |
| `actionlint` on `.github/workflows/ci.yml` | no issues |

Regression tests were run against the pre-fix code where a fix was made, and fail there.
