import { admin } from 'better-auth/plugins/admin';
import { twoFactor } from 'better-auth/plugins/two-factor';
import { username } from 'better-auth/plugins/username';
import {
  createNestAuthHarness,
  expectNoScjwt,
  expectScjwt,
  PASSWORD,
  sessionIdOf,
  type AuthClient,
  type HttpResponse,
} from './support/nest-auth-harness.js';

type UserRecord = { id: string; email: string };
type SessionRecord = { id: string };

/** Raw `Set-Cookie` value of the pending two-factor challenge cookie. */
function challengeCookie(response: HttpResponse): string {
  const values = response.headers['set-cookie'];
  const setCookies = Array.isArray(values) ? values : values ? [values] : [];
  const pair = setCookies
    .map((value: string) => value.split(';')[0])
    .find((value: string) => /two_factor=.+/.test(value));
  if (!pair) {
    throw new Error('The sign-in response did not start a two-factor challenge.');
  }
  return pair;
}

/** OTP codes delivered per user id; filled by the plugin's `sendOTP`. */
const codes = new Map<string, string>();

function createTwoFactorHarness() {
  return createNestAuthHarness({
    name: 'two-factor',
    additionalPlugins: [
      twoFactor({
        otpOptions: {
          sendOTP: async ({ user, otp }) => {
            codes.set(user.id, otp);
          },
        },
      }),
      username(),
      admin(),
    ],
  });
}

describe('NestJS two-factor (OTP) profile', () => {
  let harness: Awaited<ReturnType<typeof createTwoFactorHarness>>;
  let cookieName: string;
  let sequence = 0;

  beforeAll(async () => {
    harness = await createTwoFactorHarness();
    cookieName = harness.sessionCookieName;
  });

  afterAll(async () => {
    vi.useRealTimers();
    await harness?.close();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  /** Signs up a user and enrolls OTP two-factor; returns the post-enrollment token. */
  async function enrolledUser(extra: Record<string, string> = {}) {
    sequence += 1;
    const email = `two-factor-${sequence}@example.com`;
    const client = harness.createClient();
    const signup = await client.post('/api/auth/sign-up/email', {
      name: 'Two Factor User',
      email,
      password: PASSWORD,
      ...extra,
    });
    expect(signup.status).toBe(200);
    const signupToken = expectScjwt(signup, cookieName);
    const enabled = await client.post('/api/auth/two-factor/enable', {
      password: PASSWORD,
      method: 'otp',
    });
    expect(enabled.status).toBe(200);
    expect(enabled.body).toEqual({ method: 'otp' });
    const token = expectScjwt(enabled, cookieName);
    return {
      client,
      email,
      signupToken,
      token,
      user: signup.body.user as UserRecord,
    };
  }

  /** Starts a password sign-in and asserts it stops at the challenge. */
  async function startChallenge(client: AuthClient, path: string, body: object) {
    const response = await client.post(path, body);
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ twoFactorRedirect: true });
    expectNoScjwt(response, cookieName);
    expect((await client.get('/me')).status).toBe(401);
    return response;
  }

  it('rotates the session when OTP two-factor is enrolled', async () => {
    const { signupToken, token } = await enrolledUser();
    expect(sessionIdOf(token)).not.toBe(sessionIdOf(signupToken));
    expect((await harness.getWithToken('/me', signupToken)).status).toBe(401);
    expect((await harness.getWithToken('/me', token)).status).toBe(200);
  });

  it('issues an SCJWT only after the correct OTP and never for a replayed challenge', async () => {
    const owner = await enrolledUser();
    const client = harness.createClient();
    const pending = await startChallenge(client, '/api/auth/sign-in/email', {
      email: owner.email,
      password: PASSWORD,
    });
    const challenge = challengeCookie(pending);

    const sent = await client.post('/api/auth/two-factor/send-otp', {});
    expect(sent.status).toBe(200);
    const code = codes.get(owner.user.id);
    expect(code).toBeDefined();

    const wrong = await client.post('/api/auth/two-factor/verify-otp', {
      code: code === '000000' ? '111111' : '000000',
    });
    expect(wrong.status).toBe(401);
    expect(wrong.body.code).toBe('INVALID_CODE');
    expectNoScjwt(wrong, cookieName);

    const verified = await client.post('/api/auth/two-factor/verify-otp', {
      code,
    });
    expect(verified.status).toBe(200);
    const token = expectScjwt(verified, cookieName);
    expect((await client.get('/me')).body).toEqual({
      id: owner.user.id,
      email: owner.email,
    });

    const replay = await harness
      .createClient()
      .post('/api/auth/two-factor/verify-otp', { code }, { Cookie: challenge });
    expect(replay.status).toBe(401);
    expectNoScjwt(replay, cookieName);

    const signedOut = await client.post('/api/auth/sign-out', {});
    expect(signedOut.status).toBe(200);
    expect((await harness.getWithToken('/me', token)).status).toBe(401);
  });

  it('issues no SCJWT for an expired OTP', async () => {
    const owner = await enrolledUser();
    const client = harness.createClient();
    await startChallenge(client, '/api/auth/sign-in/email', {
      email: owner.email,
      password: PASSWORD,
    });
    expect((await client.post('/api/auth/two-factor/send-otp', {})).status).toBe(
      200,
    );
    // The default OTP period is three minutes; the challenge cookie lasts ten.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 4 * 60 * 1000);
    const expired = await client.post('/api/auth/two-factor/verify-otp', {
      code: codes.get(owner.user.id),
    });
    expect(expired.status).toBeGreaterThanOrEqual(400);
    expect(expired.body.code).toBe('OTP_HAS_EXPIRED');
    expectNoScjwt(expired, cookieName);
  });

  it('applies the challenge to username sign-in and exposes the verified session to Admin', async () => {
    const administrator = harness.createClient();
    const adminSignup = await administrator.post('/api/auth/sign-up/email', {
      name: 'Two Factor Admin',
      email: 'two-factor-admin@example.com',
      password: PASSWORD,
    });
    expect(adminSignup.status).toBe(200);
    await harness.context.internalAdapter.updateUser(
      (adminSignup.body.user as UserRecord).id,
      { role: 'admin' },
    );

    const owner = await enrolledUser({ username: 'two_factor_user' });
    const client = harness.createClient();
    await startChallenge(client, '/api/auth/sign-in/username', {
      username: 'Two_Factor_User',
      password: PASSWORD,
    });
    expect((await client.post('/api/auth/two-factor/send-otp', {})).status).toBe(
      200,
    );
    const verified = await client.post('/api/auth/two-factor/verify-otp', {
      code: codes.get(owner.user.id),
    });
    expect(verified.status).toBe(200);
    const token = expectScjwt(verified, cookieName);

    const listed = await administrator.post(
      '/api/auth/admin/list-user-sessions',
      { userId: owner.user.id },
    );
    expect(listed.status).toBe(200);
    expect(
      (listed.body.sessions as SessionRecord[]).map((session) => session.id),
    ).toContain(sessionIdOf(token));
  });

  it('rotates the session when two-factor is disabled and then signs in directly', async () => {
    const owner = await enrolledUser();
    const disabled = await owner.client.post('/api/auth/two-factor/disable', {
      password: PASSWORD,
    });
    expect(disabled.status).toBe(200);
    const token = expectScjwt(disabled, cookieName);
    expect(sessionIdOf(token)).not.toBe(sessionIdOf(owner.token));
    expect((await harness.getWithToken('/me', owner.token)).status).toBe(401);
    expect((await harness.getWithToken('/me', token)).status).toBe(200);

    const direct = await harness.createClient().post('/api/auth/sign-in/email', {
      email: owner.email,
      password: PASSWORD,
    });
    expect(direct.status).toBe(200);
    expectScjwt(direct, cookieName);
  });
});
