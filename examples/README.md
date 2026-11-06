# Framework examples

Framework examples exercise `better-auth-scjwt` through production-style applications rather than test-only adapters. Each framework lives in `examples/<framework>` and owns its unit tests in `test/unit` and HTTP-level integration tests in `test/e2e`. Tests must use isolated local resources and must not depend on a developer's production database or credentials.

## NestJS

`examples/nestjs` is a Bun-run NestJS application generated with the Nest CLI. It uses the community-maintained `@thallesp/nestjs-better-auth` Express integration, Better Auth 1.7.18's Bun-native SQLite support, email/password authentication, and the local `better-auth-scjwt` package. Nest body parsing is disabled at application creation so the Better Auth integration can consume auth request bodies correctly.
The app registers a narrow Nest exception filter for Better Auth `APIError` values so invalid or revoked SCJWTs encountered by the integration's global guard retain their `401` status instead of becoming generic server errors.
The example's build and test lifecycle rebuilds the root package and refreshes its local Bun dependency before loading the package exports, so a clean checkout never consumes a stale `dist`.

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

Test-only integrations live in `test/e2e/support/plugin-fixtures.ts`: an ephemeral local Bun server stands in for the Cloudflare Turnstile siteverify endpoint (via `siteVerifyURLOverride`), and OTP codes are generated deterministically and captured in memory. They are fixtures, not production email or captcha implementations; no external service or credential is used.

### Install and test

Run from the repository root:

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

The migration command uses Better Auth's CLI through `bunx --bun`; no Node runtime is required.
