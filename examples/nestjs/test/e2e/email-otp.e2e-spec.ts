import { emailOTP } from 'better-auth/plugins/email-otp';
import {
  createNestAuthHarness,
  expectNoScjwt,
  expectScjwt,
  PASSWORD,
  sessionIdOf,
  type AuthClient,
  type ProfileHarness,
} from './support/nest-auth-harness.js';
import { createOtpCapture } from './support/plugin-fixtures.js';

const NEW_PASSWORD = 'email-otp-new-password';

async function signUp(client: AuthClient, email: string) {
  const response = await client.post('/api/auth/sign-up/email', {
    name: 'OTP User',
    email,
    password: PASSWORD,
  });
  expect(response.status).toBe(200);
  return response;
}

async function passwordSignIn(
  client: AuthClient,
  email: string,
  password = PASSWORD,
) {
  return client.post('/api/auth/sign-in/email', { email, password });
}

async function otpSignIn(
  client: AuthClient,
  email: string,
  otp: string,
  cookieName: string,
) {
  const response = await client.post('/api/auth/sign-in/email-otp', {
    email,
    otp,
  });
  expect(response.status).toBe(200);
  const token = expectScjwt(response, cookieName);
  expect((await client.get('/api/auth/get-session')).status).toBe(200);
  expect((await client.get('/me')).status).toBe(200);
  return token;
}

function otpOptions(capture: ReturnType<typeof createOtpCapture>) {
  return { ...capture.options };
}

describe('NestJS email OTP profile', () => {
  let harness: ProfileHarness<[ReturnType<typeof emailOTP>]>;
  let cookieName: string;
  const capture = createOtpCapture();

  beforeAll(async () => {
    harness = await createNestAuthHarness({
      name: 'email-otp',
      additionalPlugins: [
        emailOTP({
          ...otpOptions(capture),
          allowedAttempts: 3,
          changeEmail: { enabled: true, verifyCurrentEmail: true },
        }),
      ],
      emailAndPassword: { revokeSessionsOnPasswordReset: true },
    });
    cookieName = harness.sessionCookieName;
  });

  afterAll(async () => {
    await harness?.close();
  });

  it('signs in existing and auto-registering users with OTP', async () => {
    const existingEmail = 'otp-existing@example.com';
    const signup = await signUp(harness.createClient(), existingEmail);
    expectScjwt(signup, cookieName);

    const existing = harness.createClient();
    const sent = await existing.post(
      '/api/auth/email-otp/send-verification-otp',
      {
        email: existingEmail,
        type: 'sign-in',
      },
    );
    expect(sent.status).toBe(200);
    const existingToken = await otpSignIn(
      existing,
      existingEmail,
      capture.latest(existingEmail, 'sign-in'),
      cookieName,
    );
    expect(sessionIdOf(existingToken)).toBe(
      sessionIdOf(existing.token() ?? existingToken),
    );

    const autoEmail = 'otp-auto@example.com';
    const auto = harness.createClient();
    expect(
      (
        await auto.post('/api/auth/email-otp/send-verification-otp', {
          email: autoEmail,
          type: 'sign-in',
        })
      ).status,
    ).toBe(200);
    await otpSignIn(
      auto,
      autoEmail,
      capture.latest(autoEmail, 'sign-in'),
      cookieName,
    );
  });

  it('checks without consuming, rejects replay and wrong codes, and enforces attempts', async () => {
    const email = 'otp-check@example.com';
    await signUp(harness.createClient(), email);
    const sender = harness.createClient();
    expect(
      (
        await sender.post('/api/auth/email-otp/send-verification-otp', {
          email,
          type: 'sign-in',
        })
      ).status,
    ).toBe(200);
    const otp = capture.latest(email, 'sign-in');
    const check = await sender.post(
      '/api/auth/email-otp/check-verification-otp',
      {
        email,
        type: 'sign-in',
        otp,
      },
    );
    expect(check.status).toBe(200);
    expect(check.body).toEqual({ success: true });
    await otpSignIn(sender, email, otp, cookieName);

    const replay = await harness
      .createClient()
      .post('/api/auth/sign-in/email-otp', { email, otp });
    expect(replay.status).toBe(400);
    expect(replay.body.code).toBe('INVALID_OTP');
    expectNoScjwt(replay, cookieName);

    const exhaustedEmail = 'otp-exhausted@example.com';
    await signUp(harness.createClient(), exhaustedEmail);
    const exhausted = harness.createClient();
    await exhausted.post('/api/auth/email-otp/send-verification-otp', {
      email: exhaustedEmail,
      type: 'sign-in',
    });
    const correct = capture.latest(exhaustedEmail, 'sign-in');
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const wrong = await exhausted.post('/api/auth/sign-in/email-otp', {
        email: exhaustedEmail,
        otp: '000000',
      });
      expect(wrong.status).toBe(400);
      expect(wrong.body.code).toBe('INVALID_OTP');
      expectNoScjwt(wrong, cookieName);
    }
    const locked = await exhausted.post('/api/auth/sign-in/email-otp', {
      email: exhaustedEmail,
      otp: correct,
    });
    expect(locked.status).toBe(403);
    expect(locked.body.code).toBe('TOO_MANY_ATTEMPTS');
    expectNoScjwt(locked, cookieName);
  });

  it('verifies email and reports the native auto-sign-in behavior', async () => {
    const email = 'otp-verify@example.com';
    const client = harness.createClient();
    const created = await signUp(client, email);
    expectScjwt(created, cookieName);
    const found = await harness.context.internalAdapter.findUserByEmail(email);
    expect(found).toBeDefined();
    if (found) {
      await harness.context.internalAdapter.updateUser(found.user.id, {
        emailVerified: false,
      });
    }
    await client.post('/api/auth/email-otp/send-verification-otp', {
      email,
      type: 'email-verification',
    });
    const response = await client.post('/api/auth/email-otp/verify-email', {
      email,
      otp: capture.latest(email, 'email-verification'),
    });
    expect(response.status).toBe(200);
    expect(response.body.status).toBe(true);
    expect(response.body.token).toBeNull();
    expectNoScjwt(response, cookieName);
    const session = await client.get('/api/auth/get-session');
    expect(session.status).toBe(200);
    expect(session.body.user.emailVerified).toBe(true);
  });

  it('resets credentials, revokes every old session, and does not issue a token', async () => {
    const email = 'otp-reset@example.com';
    const first = harness.createClient();
    const firstSignup = await signUp(first, email);
    const firstToken = expectScjwt(firstSignup, cookieName);
    const second = harness.createClient();
    const secondSignIn = await passwordSignIn(second, email);
    const secondToken = expectScjwt(secondSignIn, cookieName);

    const resetClient = harness.createClient();
    await resetClient.post('/api/auth/email-otp/request-password-reset', {
      email,
    });
    const otp = capture.latest(email, 'forget-password');
    const reset = await resetClient.post('/api/auth/email-otp/reset-password', {
      email,
      otp,
      password: NEW_PASSWORD,
    });
    expect(reset.status).toBe(200);
    expect(reset.body).toEqual({ success: true });
    expectNoScjwt(reset, cookieName);
    expect((await harness.getWithToken('/me', firstToken)).status).toBe(401);
    expect((await harness.getWithToken('/me', secondToken)).status).toBe(401);
    expect((await passwordSignIn(harness.createClient(), email)).status).toBe(
      401,
    );
    const newSignIn = await passwordSignIn(
      harness.createClient(),
      email,
      NEW_PASSWORD,
    );
    expect(newSignIn.status).toBe(200);
    expectScjwt(newSignIn, cookieName);

    const badResetClient = harness.createClient();
    await badResetClient.post('/api/auth/email-otp/request-password-reset', {
      email,
    });
    const bad = await badResetClient.post(
      '/api/auth/email-otp/reset-password',
      {
        email,
        otp: '000000',
        password: PASSWORD,
      },
    );
    expect(bad.status).toBe(400);
    expect(bad.body.code).toBe('INVALID_OTP');
    expectNoScjwt(bad, cookieName);
    const stillNew = await passwordSignIn(
      harness.createClient(),
      email,
      NEW_PASSWORD,
    );
    expect(stillNew.status).toBe(200);
    const replay = await badResetClient.post(
      '/api/auth/email-otp/reset-password',
      {
        email,
        otp,
        password: PASSWORD,
      },
    );
    expect(replay.status).toBe(400);
    expectNoScjwt(replay, cookieName);
    expect(
      (await passwordSignIn(harness.createClient(), email, NEW_PASSWORD))
        .status,
    ).toBe(200);
    expect(stillNew.body.user.email).toBe(email);
  });

  it('changes email through current and new email OTPs while preserving other sessions', async () => {
    const email = 'otp-change-old@example.com';
    const newEmail = 'otp-change-new@example.com';
    await signUp(harness.createClient(), email);
    const clientA = harness.createClient();
    const signInA = await passwordSignIn(clientA, email);
    const tokenA = expectScjwt(signInA, cookieName);
    const clientB = harness.createClient();
    const signInB = await passwordSignIn(clientB, email);
    const tokenB = expectScjwt(signInB, cookieName);

    await clientA.post('/api/auth/email-otp/send-verification-otp', {
      email,
      type: 'email-verification',
    });
    const requested = await clientA.post(
      '/api/auth/email-otp/request-email-change',
      {
        newEmail,
        otp: capture.latest(email, 'email-verification'),
      },
    );
    expect(requested.status).toBe(200);
    const changed = await clientA.post('/api/auth/email-otp/change-email', {
      newEmail,
      otp: capture.latest(newEmail, 'change-email'),
    });
    expect(changed.status).toBe(200);
    const replacement = expectScjwt(changed, cookieName);
    expect(sessionIdOf(replacement)).toBe(sessionIdOf(tokenA));
    expect(
      (await clientA.get('/api/auth/get-session')).body.user,
    ).toMatchObject({
      email: newEmail,
      emailVerified: true,
    });
    expect((await harness.getWithToken('/me', tokenB)).status).toBe(200);
    expect((await clientB.get('/api/auth/get-session')).body.user.email).toBe(
      newEmail,
    );

    const wrongCurrent = await clientA.post(
      '/api/auth/email-otp/request-email-change',
      {
        newEmail: 'otp-wrong-current@example.com',
        otp: '000000',
      },
    );
    expect(wrongCurrent.status).toBe(400);
    expect((await clientA.get('/api/auth/get-session')).body.user.email).toBe(
      newEmail,
    );

    await clientA.post('/api/auth/email-otp/send-verification-otp', {
      email: newEmail,
      type: 'email-verification',
    });
    const secondTarget = 'otp-change-wrong-new@example.com';
    expect(
      (
        await clientA.post('/api/auth/email-otp/request-email-change', {
          newEmail: secondTarget,
          otp: capture.latest(newEmail, 'email-verification'),
        })
      ).status,
    ).toBe(200);
    const wrongNew = await clientA.post('/api/auth/email-otp/change-email', {
      newEmail: secondTarget,
      otp: '000000',
    });
    expect(wrongNew.status).toBe(400);
    expect((await clientA.get('/api/auth/get-session')).body.user.email).toBe(
      newEmail,
    );
    const secondOtp = capture.latest(secondTarget, 'change-email');
    const changedAgain = await clientA.post(
      '/api/auth/email-otp/change-email',
      {
        newEmail: secondTarget,
        otp: secondOtp,
      },
    );
    expect(changedAgain.status).toBe(200);
    const replay = await clientA.post('/api/auth/email-otp/change-email', {
      newEmail: secondTarget,
      otp: secondOtp,
    });
    expect(replay.status).toBe(400);
    expect((await clientA.get('/api/auth/get-session')).body.user.email).toBe(
      secondTarget,
    );
  });
});

describe('NestJS email OTP isolated options', () => {
  it('rejects unknown users when sign-up is disabled', async () => {
    const capture = createOtpCapture();
    const harness = await createNestAuthHarness({
      name: 'email-otp-no-signup',
      additionalPlugins: [
        emailOTP({ ...capture.options, disableSignUp: true }),
      ],
    });
    try {
      const client = harness.createClient();
      const send = await client.post(
        '/api/auth/email-otp/send-verification-otp',
        {
          email: 'disabled@example.com',
          type: 'sign-in',
        },
      );
      expect(send.status).toBe(200);
      expect(capture.count('disabled@example.com', 'sign-in')).toBe(0);
      const response = await client.post('/api/auth/sign-in/email-otp', {
        email: 'disabled@example.com',
        otp: '100001',
      });
      expect(response.status).toBe(400);
      expect(response.body.code).toBe('INVALID_OTP');
      expectNoScjwt(response, harness.sessionCookieName);
      expect(
        await harness.context.internalAdapter.findUserByEmail(
          'disabled@example.com',
        ),
      ).toBeNull();
    } finally {
      await harness.close();
    }
  });

  it('rotates OTPs and accepts only the latest code', async () => {
    const capture = createOtpCapture();
    const harness = await createNestAuthHarness({
      name: 'email-otp-rotate',
      additionalPlugins: [
        emailOTP({ ...capture.options, resendStrategy: 'rotate' }),
      ],
    });
    try {
      const email = 'rotate@example.com';
      const client = harness.createClient();
      await client.post('/api/auth/email-otp/send-verification-otp', {
        email,
        type: 'sign-in',
      });
      const oldOtp = capture.latest(email, 'sign-in');
      await client.post('/api/auth/email-otp/send-verification-otp', {
        email,
        type: 'sign-in',
      });
      const latest = capture.latest(email, 'sign-in');
      expect(latest).not.toBe(oldOtp);
      const old = await client.post('/api/auth/sign-in/email-otp', {
        email,
        otp: oldOtp,
      });
      expect(old.status).toBe(400);
      expect(old.body.code).toBe('INVALID_OTP');
      expectNoScjwt(old, harness.sessionCookieName);
      await otpSignIn(client, email, latest, harness.sessionCookieName);
    } finally {
      await harness.close();
    }
  });

  it('reuses the same OTP', async () => {
    const capture = createOtpCapture();
    const harness = await createNestAuthHarness({
      name: 'email-otp-reuse',
      additionalPlugins: [
        // `reuse` requires a recoverable OTP; plain is the default, stated explicitly.
        emailOTP({
          ...capture.options,
          resendStrategy: 'reuse',
          storeOTP: 'plain',
        }),
      ],
    });
    try {
      const email = 'reuse@example.com';
      const client = harness.createClient();
      await client.post('/api/auth/email-otp/send-verification-otp', {
        email,
        type: 'sign-in',
      });
      const first = capture.latest(email, 'sign-in');
      await client.post('/api/auth/email-otp/send-verification-otp', {
        email,
        type: 'sign-in',
      });
      expect(capture.latest(email, 'sign-in')).toBe(first);
      expect(capture.count(email, 'sign-in')).toBe(2);
      await otpSignIn(client, email, first, harness.sessionCookieName);
    } finally {
      await harness.close();
    }
  });

  it('rejects expired OTPs', async () => {
    const capture = createOtpCapture();
    const harness = await createNestAuthHarness({
      name: 'email-otp-expiry',
      additionalPlugins: [emailOTP({ ...capture.options, expiresIn: 1 })],
    });
    try {
      const email = 'expiry@example.com';
      const client = harness.createClient();
      await client.post('/api/auth/email-otp/send-verification-otp', {
        email,
        type: 'sign-in',
      });
      const otp = capture.latest(email, 'sign-in');
      await Bun.sleep(1500);
      const response = await client.post('/api/auth/sign-in/email-otp', {
        email,
        otp,
      });
      expect(response.status).toBe(400);
      expect(response.body.code).toBe('OTP_EXPIRED');
      expectNoScjwt(response, harness.sessionCookieName);
    } finally {
      await harness.close();
    }
  });
});
