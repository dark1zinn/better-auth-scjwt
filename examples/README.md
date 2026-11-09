# Framework examples

Framework examples exercise `better-auth-scjwt` through production-style applications rather than test-only adapters. Each framework lives in `examples/<framework>` and owns its unit tests in `test/unit` and HTTP-level integration tests in `test/e2e`. Tests must use isolated local resources and must not depend on a developer's production database or credentials.

## NestJS

`examples/nestjs` is a Bun-run NestJS application generated with the Nest CLI. It uses the community-maintained `@thallesp/nestjs-better-auth` Express integration, Better Auth 1.7.18's Bun-native SQLite support, email/password authentication, and the local `better-auth-scjwt` package. Nest body parsing is disabled at application creation so the Better Auth integration can consume auth request bodies correctly.
The app registers a narrow Nest exception filter for Better Auth `APIError` values so invalid or revoked SCJWTs encountered by the integration's global guard retain their `401` status instead of becoming generic server errors.
The example consumes the root package through `file:../..`. Its `build`, `test`, and `test:e2e` scripts first run `sync:scjwt`, which rebuilds the root `dist` and refreshes the local copy with `bun install --frozen-lockfile --ignore-scripts --force`, so tests never load a stale `dist` and a refresh can neither rerun lifecycle scripts nor change locked dependency versions.

The only application-owned routes are:

- `GET /health`, an anonymous health check;
- `GET /me`, a globally guarded route that returns only the authenticated user's id and email.

Better Auth owns the `/api/auth/*` routes.

### Source layout

- `src/auth.factory.ts` — import-safe `createAuth(...)`: opens the SQLite file, enables email/password, and registers `[scjwt(), ...additionalPlugins]`. SCJWT is always first so session-dependent plugin hooks see the SCJWT-resolved session.
- `src/auth.ts` — the production singleton: reads `BETTER_AUTH_DATABASE`, `BETTER_AUTH_URL`, and `BETTER_AUTH_SECRET` and calls the factory with no additional plugins. The runnable application is SCJWT-only.
- `src/app-module.metadata.ts` — module wiring shared by `AppModule` and the E2E profiles.

### E2E profiles

Each profile file builds its own Better Auth instance through the factory, a unique SQLite database under the ignored `test/.data/`, fresh migrations, and its own Nest application (`test/e2e/support/nest-auth-harness.ts`). Every actor uses an independent Supertest agent and cookie jar. All behavior runs over HTTP (`/api/auth/*`, `/me`).

| Profile | Plugins after `scjwt()` | Proves |
|---|---|---|
| `scjwt-only` | none | Sign-up/in, session lookup/listing, targeted and session-wide revocation, password change, sign-out, invalid credentials and SCJWTs |
| `admin` | `admin()` | Denial for anonymous/ordinary users, user CRUD, roles, ban/unban, session revocation, impersonation with `admin_session` restoration, password set, user removal |
| `rbac` | `admin({ ac, roles })` | Custom `project` statement, `auditor` role, `has-permission`, role changes observed by existing SCJWTs without new sessions |
| `i18n` | `i18n()` | Header/cookie/stored-user locale detection on translated errors |
| `captcha` | `captcha()` | Missing/rejected/unavailable verification blocks issuance and mutations; accepted requests issue SCJWTs |
| `username` | `username()` | Normalization, username sign-in, availability, validation, `update-user`, `immutableUsername` |
| `email-otp` | `emailOTP()` | OTP sign-in/auto-registration, attempts, replay, expiry, resend strategies, verification, password reset revocation, two-stage email change |
| `combined-plugins` | `admin`, `captcha`, `username`, `emailOTP`, `i18n` | All of the above composed in one application |
| `two-factor` | `twoFactor({ otpOptions })`, `username`, `admin` | OTP enrollment and disabling rotate the session; password and username sign-in stop at the challenge with no live session cookie; wrong and expired codes and a replayed challenge issue nothing; the verified session is a normal SCJWT session visible to Admin and ended by sign-out |

The `two-factor` profile covers the OTP method only, with codes captured in memory by `sendOTP`. TOTP, backup codes, trusted devices, passkeys, and OAuth-provider MFA are not exercised. Header placement during a pending challenge is covered by the root suite (`test/lifecycle-finalization.test.ts`), where the challenge cookie is the only cookie the client must return.

Within a profile file, cases share only the Nest application and local fixtures. In `combined-plugins` every case signs up its own users and administrators with unique addresses, proves email ownership through the real OTP flow where it needs it, and uses its own clients, so a case passes on its own (`-t "<title>"`), in any order (`--sequence.shuffle`), and does not depend on accounts, tokens, or passwords left behind by another case.

Test-only integrations live in `test/e2e/support/plugin-fixtures.ts`: an ephemeral local Bun server stands in for the Cloudflare Turnstile siteverify endpoint (via `siteVerifyURLOverride`), and OTP codes are generated deterministically and captured in memory. They are fixtures, not production email or captcha implementations; no external service or credential is used.

### Install and test

Run from the repository root. The first `bun install` is an ordinary install (third-party lifecycle scripts run as usual); installing never builds or deletes anything in this repository, because the root package only builds in `prepack` and through `sync:scjwt`:

```bash
bun install
bun run build
bun run --cwd examples/nestjs test
bun run --cwd examples/nestjs test:e2e
bun run --cwd examples/nestjs build
```

Run a single profile from `examples/nestjs` (after `bun run sync:scjwt`):

```bash
bunx --bun vitest run --config vitest.config.e2e.ts test/e2e/combined-plugins.e2e-spec.ts
```

### Run the application

Copy the environment template and replace its placeholder secret:

```bash
cp examples/nestjs/.env.example examples/nestjs/.env
bun run --cwd examples/nestjs auth:migrate
bun run --cwd examples/nestjs start:dev
```

- `BETTER_AUTH_DATABASE`: path to the file-backed SQLite database;
- `BETTER_AUTH_URL`: externally reachable application base URL;
- `BETTER_AUTH_SECRET`: high-entropy secret with at least 32 characters.

`auth:migrate` runs the Better Auth CLI (`auth`) pinned as an exact `1.7.18` dev dependency and locked in `bun.lock`, so migrations always use the same Better Auth line as the application rather than whatever `auth@latest` resolves to. It runs under Bun (`bunx --bun`) and is idempotent: a second run reports that no migrations are needed. Upgrade it together with `better-auth`.
