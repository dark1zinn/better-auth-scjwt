import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { Database } from 'bun:sqlite';
import { betterAuth } from 'better-auth';

type RequiredEnvironmentVariable =
  | 'BETTER_AUTH_DATABASE'
  | 'BETTER_AUTH_SECRET'
  | 'BETTER_AUTH_URL';

function requiredEnv(name: RequiredEnvironmentVariable): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} must be configured.`);
  }
  return value;
}

const databasePath = resolve(requiredEnv('BETTER_AUTH_DATABASE'));
mkdirSync(dirname(databasePath), { recursive: true });

export const auth = betterAuth({
  database: new Database(databasePath),
  baseURL: requiredEnv('BETTER_AUTH_URL'),
  secret: requiredEnv('BETTER_AUTH_SECRET'),
  emailAndPassword: { enabled: true },
});
