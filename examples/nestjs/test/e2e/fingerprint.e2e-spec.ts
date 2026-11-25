import type { ScjwtFingerprintOptions } from 'better-auth-scjwt';
import {
  createNestAuthHarness,
  expectNoScjwt,
  expectScjwt,
  PASSWORD,
  sessionIdOf,
  type AuthClient,
  type ProfileHarness,
} from './support/nest-auth-harness.js';

type Mode = NonNullable<ScjwtFingerprintOptions['mode']>;
type Harness = ProfileHarness<[]>;

/** Device headers for one request; they override the harness defaults. */
function device(
  ip: string,
  userAgent = 'better-auth-scjwt-nestjs-e2e',
  platform = '"Linux"',
): Record<string, string> {
  return {
    'X-Forwarded-For': ip,
    'User-Agent': userAgent,
    'Sec-CH-UA-Platform': platform,
  };
}

/** Runs `body` against a fresh application using the given fingerprint mode. */
async function withMode(
  mode: Mode,
  body: (harness: Harness) => Promise<void>,
): Promise<void> {
  const harness = await createNestAuthHarness({
    name: `fingerprint-${mode}`,
    additionalPlugins: [],
    scjwt: { fingerprint: { mode } },
  });
  try {
    await body(harness);
  } finally {
    await harness.close();
  }
}

async function signUp(
  harness: Harness,
  client: AuthClient,
  email: string,
  from: Record<string, string>,
): Promise<string> {
  const response = await client.post(
    '/api/auth/sign-up/email',
    { name: 'Fingerprint User', email, password: PASSWORD },
    from,
  );
  expect(response.status).toBe(200);
  return expectScjwt(response, harness.sessionCookieName);
}

/** Asserts a signed-out read that clears the client's SCJWT cookie. */
async function expectSignedOutRead(
  client: AuthClient,
  from: Record<string, string>,
): Promise<void> {
  const read = await client.get('/api/auth/get-session', from);
  expect(read.status).toBe(200);
  expect(JSON.parse(read.text)).toBeNull();
  expect(client.token()).toBeUndefined();
}

describe('NestJS SCJWT fingerprint modes', () => {
  it('strict: a changed User-Agent signs out until the client signs in again', () =>
    withMode('strict', async (harness) => {
      const email = 'fingerprint-strict@example.com';
      const client = harness.createClient();
      const home = device('203.0.113.10');
      await signUp(harness, client, email, home);
      expect((await client.get('/me', home)).status).toBe(200);

      const newBrowser = device('203.0.113.10', 'another-browser/2.0');
      expect((await client.get('/me', newBrowser)).status).toBe(401);
      await expectSignedOutRead(client, newBrowser);

      const signIn = await client.post(
        '/api/auth/sign-in/email',
        { email, password: PASSWORD },
        newBrowser,
      );
      expect(signIn.status).toBe(200);
      expectScjwt(signIn, harness.sessionCookieName);
      expect((await client.get('/me', newBrowser)).status).toBe(200);
    }));

  it('dynamic: keeps a token within its network, re-binds it to a new one, and signs out a combined change', () =>
    withMode('dynamic', async (harness) => {
      const client = harness.createClient();
      const original = await signUp(
        harness,
        client,
        'fingerprint-dynamic@example.com',
        device('203.0.113.10'),
      );

      const sameNetwork = await client.get(
        '/api/auth/get-session',
        device('203.0.113.200'),
      );
      expect(sameNetwork.status).toBe(200);
      expectNoScjwt(sameNetwork, harness.sessionCookieName);
      expect(client.token()).toBe(original);

      // The guard tolerates the new network but cannot deliver a replacement;
      // the next Better Auth response does.
      const mobile = device('198.51.100.20');
      expect((await client.get('/me', mobile)).status).toBe(200);
      expect(client.token()).toBe(original);
      const rebound = await client.get('/api/auth/get-session', mobile);
      expect(rebound.status).toBe(200);
      const replacement = expectScjwt(rebound, harness.sessionCookieName);
      expect(sessionIdOf(replacement)).toBe(sessionIdOf(original));
      expect(client.token()).toBe(replacement);
      expect((await client.get('/me', mobile)).status).toBe(200);

      const elsewhere = device('192.0.2.50', 'another-browser/2.0');
      expect((await client.get('/me', elsewhere)).status).toBe(401);
      await expectSignedOutRead(client, elsewhere);
    }));

  it('loose: keeps the session through every change and re-binds the token', () =>
    withMode('loose', async (harness) => {
      const client = harness.createClient();
      const original = await signUp(
        harness,
        client,
        'fingerprint-loose@example.com',
        device('203.0.113.10'),
      );
      const elsewhere = device(
        '198.51.100.20',
        'another-browser/2.0',
        '"Windows"',
      );
      expect((await client.get('/me', elsewhere)).status).toBe(200);
      const rebound = await client.get('/api/auth/get-session', elsewhere);
      expect(rebound.status).toBe(200);
      const replacement = expectScjwt(rebound, harness.sessionCookieName);
      expect(sessionIdOf(replacement)).toBe(sessionIdOf(original));
      expect((await client.get('/me', elsewhere)).status).toBe(200);
    }));
});
