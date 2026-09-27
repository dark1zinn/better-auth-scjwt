# Framework examples

Framework examples exercise `better-auth-scjwt` through production-style applications rather than test-only adapters. Each framework lives in `examples/<framework>` and owns its unit tests in `test/unit` and HTTP-level integration tests in `test/e2e`. Tests must use isolated local resources and must not depend on a developer's production database or credentials.

## NestJS

`examples/nestjs` is a Bun-run NestJS application generated with the Nest CLI. It uses the community-maintained `@thallesp/nestjs-better-auth` Express integration, Better Auth's Bun-native SQLite support, email/password authentication, and the local `better-auth-scjwt` package. Nest body parsing is disabled at application creation so the Better Auth integration can consume auth request bodies correctly.
The app registers a narrow Nest exception filter for Better Auth `APIError` values so invalid or revoked SCJWTs encountered by the integration's global guard retain their `401` status instead of becoming generic server errors.
The example's build and test lifecycle rebuilds the root package and refreshes its local Bun dependency before loading the package exports, so a clean checkout never consumes a stale `dist`.

The only application-owned routes are:

- `GET /health`, an anonymous health check;
- `GET /me`, a globally guarded route that returns only the authenticated user's id and email.

Better Auth owns the `/api/auth/*` routes. The E2E suite covers sign-up, sign-in, session lookup and listing, targeted/session-wide revocation, password changes, sign-out, invalid credentials, invalid SCJWTs, and Nest's global route guard.

### Install and test

Run from the repository root:

```bash
bun install
bun run build
bun run --cwd examples/nestjs test
bun run --cwd examples/nestjs test:e2e
bun run --cwd examples/nestjs build
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
