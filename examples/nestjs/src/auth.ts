import { createAuth } from './auth.factory.js';

type RequiredEnvironmentVariable =
  'BETTER_AUTH_DATABASE' | 'BETTER_AUTH_SECRET' | 'BETTER_AUTH_URL';

function requiredEnv(name: RequiredEnvironmentVariable): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} must be configured.`);
  }
  return value;
}

export const auth = createAuth({
  databasePath: requiredEnv('BETTER_AUTH_DATABASE'),
  baseURL: requiredEnv('BETTER_AUTH_URL'),
  secret: requiredEnv('BETTER_AUTH_SECRET'),
  additionalPlugins: [],
});
