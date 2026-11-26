import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { Database } from 'bun:sqlite';
import {
  betterAuth,
  type BetterAuthOptions,
  type BetterAuthPlugin,
} from 'better-auth';
import { scjwt, type ScjwtOptions } from 'better-auth-scjwt';

export interface CreateAuthOptions<
  AdditionalPlugins extends BetterAuthPlugin[],
> {
  databasePath: string;
  baseURL: string;
  secret: string;
  /** Registered after SCJWT so their hooks observe the SCJWT-resolved session. */
  additionalPlugins: AdditionalPlugins;
  emailAndPassword?: Partial<
    NonNullable<BetterAuthOptions['emailAndPassword']>
  >;
  user?: BetterAuthOptions['user'];
  session?: BetterAuthOptions['session'];
  /** Better Auth `advanced` settings, for example IP resolution. */
  advanced?: BetterAuthOptions['advanced'];
  /** Options for `scjwt()`; defaults to cookie placement and strict fingerprints. */
  scjwt?: ScjwtOptions;
}

/**
 * Builds the example Better Auth instance without reading the environment.
 *
 * SCJWT is always registered first: Better Auth runs plugin before-hooks in
 * registration order, and session-dependent plugin hooks must see the session
 * SCJWT resolved from the presented token.
 */
export function createAuth<const AdditionalPlugins extends BetterAuthPlugin[]>(
  options: CreateAuthOptions<AdditionalPlugins>,
) {
  const databasePath = resolve(options.databasePath);
  mkdirSync(dirname(databasePath), { recursive: true });

  return betterAuth({
    database: new Database(databasePath),
    baseURL: options.baseURL,
    secret: options.secret,
    emailAndPassword: { enabled: true, ...options.emailAndPassword },
    user: options.user,
    session: options.session,
    advanced: options.advanced,
    plugins: [scjwt(options.scjwt), ...options.additionalPlugins],
  });
}
