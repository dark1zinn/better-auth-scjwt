import { admin } from 'better-auth/plugins/admin';
import { captcha } from 'better-auth/plugins/captcha';
import { emailOTP } from 'better-auth/plugins/email-otp';
import { i18n } from '@better-auth/i18n';
import { username } from 'better-auth/plugins/username';
import {
  createNestAuthHarness,
  expectNoScjwt,
  expectScjwt,
  PASSWORD,
  sessionIdOf,
  type AuthClient,
  type ProfileHarness,
} from './support/nest-auth-harness.js';
import {
  CAPTCHA_PASS,
  CAPTCHA_REJECT,
  CAPTCHA_SECRET,
  captchaHeaders,
  createOtpCapture,
  i18nOptions,
  localeUserField,
  rbacAdminOptions,
  startCaptchaVerifier,
  FRENCH_TRANSLATIONS,
  type CaptchaVerifier,
} from './support/plugin-fixtures.js';

type UserRecord = {
  id: string;
  email: string;
  role?: string;
  username?: string;
  locale?: string;
};
type SessionRecord = { id: string; token: string; userId: string };

const CAPTCHA_ENDPOINTS = [
  '/sign-up/email',
  '/sign-in/email',
  '/sign-in/username',
  '/email-otp/send-verification-otp',
  '/email-otp/check-verification-otp',
  '/sign-in/email-otp',
  '/email-otp/request-password-reset',
  '/email-otp/reset-password',
  '/email-otp/request-email-change',
  '/email-otp/change-email',
  '/admin/**',
];
const OLD_PASSWORD = PASSWORD;
const NEW_PASSWORD = 'combined-reset-password-123';

type CombinedPlugins = [
  ReturnType<typeof admin>,
  ReturnType<typeof captcha>,
  ReturnType<typeof username>,
  ReturnType<typeof emailOTP>,
  ReturnType<typeof i18n>,
];

describe('NestJS combined-plugins profile', () => {
  let verifier: CaptchaVerifier;
  let harness: ProfileHarness<CombinedPlugins>;
  let cookieName: string;
  let adminClient: AuthClient;
  let userClient: AuthClient;
  let otpClient: AuthClient;
  let adminId: string;
  let userId: string;
  let userEmail: string;
  let userToken: string;
  let otpToken: string;
  const capture = createOtpCapture();

  beforeAll(async () => {
    verifier = startCaptchaVerifier();
    harness = await createNestAuthHarness({
      name: 'combined-plugins',
      additionalPlugins: [
        admin(rbacAdminOptions),
        captcha({
          provider: 'cloudflare-turnstile',
          secretKey: CAPTCHA_SECRET,
          siteVerifyURLOverride: verifier.url,
          endpoints: CAPTCHA_ENDPOINTS,
        }),
        username(),
        emailOTP({
          ...capture.options,
          changeEmail: { enabled: true, verifyCurrentEmail: true },
        }),
        i18n(i18nOptions),
      ],
      user: localeUserField,
      emailAndPassword: { revokeSessionsOnPasswordReset: true },
      dispose: [verifier.stop],
    });
    cookieName = harness.sessionCookieName;
    adminClient = harness.createClient();
    userClient = harness.createClient();
    otpClient = harness.createClient();

    const adminSignup = await adminClient.post(
      '/api/auth/sign-up/email',
      {
        name: 'Combined Admin',
        email: 'combined-admin@example.com',
        password: PASSWORD,
      },
      captchaHeaders(CAPTCHA_PASS),
    );
    expect(adminSignup.status).toBe(200);
    adminId = (adminSignup.body.user as UserRecord).id;
    await harness.context.internalAdapter.updateUser(adminId, {
      role: 'admin',
    });
    expect((await adminClient.get('/me')).status).toBe(200);
  });

  afterAll(async () => {
    await harness?.close();
  });

  /** POSTs with a captcha header; defaults to an accepted captcha response. */
  function post(
    client: AuthClient,
    path: string,
    body: object,
    response = CAPTCHA_PASS,
  ) {
    return client.post(path, body, captchaHeaders(response));
  }

  it('signs up with captcha, username, locale, and default Admin role', async () => {
    userEmail = `combined-user-${Date.now()}@example.com`;
    const absent = await harness
      .createClient()
      .post('/api/auth/sign-up/email', {
        name: 'No Captcha',
        email: 'combined-no-captcha@example.com',
        password: PASSWORD,
        username: 'no_captcha',
        locale: 'fr',
      });
    expect(absent.status).toBe(400);
    expect(absent.body.code).toBe('MISSING_RESPONSE');
    expectNoScjwt(absent, cookieName);
    expect(
      await harness.context.internalAdapter.findUserByEmail(
        'combined-no-captcha@example.com',
      ),
    ).toBeNull();

    const signup = await post(userClient, '/api/auth/sign-up/email', {
      name: 'Combined User',
      email: userEmail,
      password: PASSWORD,
      username: 'Combined_User',
      locale: 'fr',
    });
    expect(signup.status).toBe(200);
    userToken = expectScjwt(signup, cookieName);
    userId = (signup.body.user as UserRecord).id;
    expect(signup.body.user).toMatchObject({
      role: 'user',
      username: 'combined_user',
      locale: 'fr',
    });
    const session = await userClient.get('/api/auth/get-session');
    expect(session.status).toBe(200);
    expect(session.body.user).toMatchObject({
      role: 'user',
      username: 'combined_user',
      locale: 'fr',
    });
    expect((await userClient.get('/me')).body).toEqual({
      id: userId,
      email: userEmail,
    });
  });

  it('authenticates username and email OTP sessions, while captcha gates OTP delivery', async () => {
    const usernameClient = harness.createClient();
    const usernameSignin = await post(
      usernameClient,
      '/api/auth/sign-in/username',
      {
        username: 'COMBINED_USER',
        password: PASSWORD,
      },
    );
    expect(usernameSignin.status).toBe(200);
    const usernameToken = expectScjwt(usernameSignin, cookieName);
    expect(sessionIdOf(usernameToken)).not.toBe(sessionIdOf(userToken));
    expect(
      (await usernameClient.get('/api/auth/get-session')).body.user.username,
    ).toBe('combined_user');
    expect((await usernameClient.get('/me')).status).toBe(200);

    const before = capture.count(userEmail, 'sign-in');
    const rejected = await post(
      otpClient,
      '/api/auth/email-otp/send-verification-otp',
      {
        email: userEmail,
        type: 'sign-in',
      },
      CAPTCHA_REJECT,
    );
    expect(rejected.status).toBe(403);
    expect(rejected.body.code).toBe('VERIFICATION_FAILED');
    expectNoScjwt(rejected, cookieName);
    expect(capture.count(userEmail, 'sign-in')).toBe(before);

    const verificationSent = await post(
      otpClient,
      '/api/auth/email-otp/send-verification-otp',
      {
        email: userEmail,
        type: 'email-verification',
      },
    );
    expect(verificationSent.status).toBe(200);
    const verified = await post(otpClient, '/api/auth/email-otp/verify-email', {
      email: userEmail,
      otp: capture.latest(userEmail, 'email-verification'),
    });
    expect(verified.status).toBe(200);
    expectNoScjwt(verified, cookieName);

    const sent = await post(
      otpClient,
      '/api/auth/email-otp/send-verification-otp',
      {
        email: userEmail,
        type: 'sign-in',
      },
    );
    const unprovenEmail = `combined-unproven-${Date.now()}@example.com`;
    const unprovenClient = harness.createClient();
    const unprovenSignup = await post(
      unprovenClient,
      '/api/auth/sign-up/email',
      {
        name: 'Unproven User',
        email: unprovenEmail,
        password: PASSWORD,
      },
    );
    const unprovenToken = expectScjwt(unprovenSignup, cookieName);
    const unprovenUser = unprovenSignup.body.user as UserRecord;
    await harness.context.internalAdapter.updateUser(unprovenUser.id, {
      emailVerified: false,
    });
    const unprovenSend = await post(
      harness.createClient(),
      '/api/auth/email-otp/send-verification-otp',
      {
        email: unprovenEmail,
        type: 'sign-in',
      },
    );
    expect(unprovenSend.status).toBe(200);
    const unprovenSignin = await post(
      harness.createClient(),
      '/api/auth/sign-in/email-otp',
      {
        email: unprovenEmail,
        otp: capture.latest(unprovenEmail, 'sign-in'),
      },
    );
    expect(unprovenSignin.status).toBe(200);
    expectScjwt(unprovenSignin, cookieName);
    expect((await harness.getWithToken('/me', unprovenToken)).status).toBe(401);
    expect(sent.status).toBe(200);
    const otpSignin = await post(otpClient, '/api/auth/sign-in/email-otp', {
      email: userEmail,
      otp: capture.latest(userEmail, 'sign-in'),
    });
    expect(otpSignin.status).toBe(200);
    otpToken = expectScjwt(otpSignin, cookieName);
    expect(sessionIdOf(otpToken)).not.toBe(sessionIdOf(usernameToken));
    expect(
      (await otpClient.get('/api/auth/get-session')).body.user,
    ).toMatchObject({ username: 'combined_user', locale: 'fr' });
    expect((await otpClient.get('/me')).status).toBe(200);
  });

  it('localizes valid-captcha credential errors and rejects captcha before authentication', async () => {
    const wrong = await harness.createClient().post(
      '/api/auth/sign-in/email',
      {
        email: userEmail,
        password: 'wrong-password',
      },
      { ...captchaHeaders(CAPTCHA_PASS), 'Accept-Language': 'fr' },
    );
    expect(wrong.status).toBe(401);
    expect(wrong.body.code).toBe('INVALID_EMAIL_OR_PASSWORD');
    expect(wrong.body.message).toBe(
      FRENCH_TRANSLATIONS.INVALID_EMAIL_OR_PASSWORD,
    );
    expectNoScjwt(wrong, cookieName);

    const rejected = await harness.createClient().post(
      '/api/auth/sign-in/email',
      {
        email: userEmail,
        password: 'wrong-password',
      },
      { ...captchaHeaders(CAPTCHA_REJECT), 'Accept-Language': 'fr' },
    );
    expect(rejected.status).toBe(403);
    expect(rejected.body.code).toBe('VERIFICATION_FAILED');
    expectNoScjwt(rejected, cookieName);
  });

  it('updates RBAC through HTTP and enforces captcha and authorization', async () => {
    const missing = await adminClient.post('/api/auth/admin/set-role', {
      userId,
      role: 'auditor',
    });
    expect(missing.status).toBe(400);
    expect(missing.body.code).toBe('MISSING_RESPONSE');
    const changed = await post(adminClient, '/api/auth/admin/set-role', {
      userId,
      role: 'auditor',
    });
    expect(changed.status).toBe(200);
    expectNoScjwt(changed, cookieName);
    const userSession = await userClient.get('/api/auth/get-session');
    expect(userSession.status).toBe(200);
    expect(userSession.body.user.role).toBe('auditor');
    const read = await post(userClient, '/api/auth/admin/has-permission', {
      permissions: { project: ['read'] },
    });
    expect(read.status).toBe(200);
    expect(read.body).toEqual({ error: null, success: true });
    const create = await post(userClient, '/api/auth/admin/has-permission', {
      permissions: { project: ['create'] },
    });
    expect(create.body).toEqual({ error: null, success: false });
    const denied = await post(userClient, '/api/auth/admin/ban-user', {
      userId: adminId,
    });
    expect(denied.status).toBe(403);
    expectNoScjwt(denied, cookieName);
  });

  it('impersonates and restores the original administrator session', async () => {
    const original = adminClient.token();
    expect(original).toBeDefined();
    const impersonated = await post(
      adminClient,
      '/api/auth/admin/impersonate-user',
      { userId },
    );
    expect(impersonated.status).toBe(200);
    const impersonationToken = expectScjwt(impersonated, cookieName);
    expect(
      (await adminClient.get('/api/auth/get-session')).body.session
        .impersonatedBy,
    ).toBe(adminId);
    const stopped = await post(
      adminClient,
      '/api/auth/admin/stop-impersonating',
      {},
    );
    expect(stopped.status).toBe(200);
    const restored = expectScjwt(stopped, cookieName);
    expect(sessionIdOf(restored)).toBe(sessionIdOf(original as string));
    expect((await harness.getWithToken('/me', impersonationToken)).status).toBe(
      401,
    );
  });

  it('revokes one session, then bans all remaining sessions without revival', async () => {
    const listed = await post(
      adminClient,
      '/api/auth/admin/list-user-sessions',
      { userId },
    );
    expect(listed.status).toBe(200);
    const sessions = listed.body.sessions as SessionRecord[];
    const selected = sessions.find(
      (session) => session.id === sessionIdOf(userToken),
    );
    expect(selected).toBeDefined();
    const revoked = await post(
      adminClient,
      '/api/auth/admin/revoke-user-session',
      { sessionToken: selected?.token },
    );
    expect(revoked.status).toBe(200);
    expect((await harness.getWithToken('/me', userToken)).status).toBe(401);
    expect((await harness.getWithToken('/me', otpToken)).status).toBe(200);
    const banned = await post(adminClient, '/api/auth/admin/ban-user', {
      userId,
      banReason: 'combined test',
    });
    expect(banned.status).toBe(200);
    expect((await harness.getWithToken('/me', otpToken)).status).toBe(401);
    const unbanned = await post(adminClient, '/api/auth/admin/unban-user', {
      userId,
    });
    expect(unbanned.status).toBe(200);
    expect((await harness.getWithToken('/me', otpToken)).status).toBe(401);
  });

  it('resets the password, revokes pre-reset sessions, and signs in with the replacement password', async () => {
    const request = await post(
      harness.createClient(),
      '/api/auth/email-otp/request-password-reset',
      { email: userEmail },
    );
    expect(request.status).toBe(200);
    const reset = await post(
      harness.createClient(),
      '/api/auth/email-otp/reset-password',
      {
        email: userEmail,
        otp: capture.latest(userEmail, 'forget-password'),
        password: NEW_PASSWORD,
      },
    );
    expect(reset.status).toBe(200);
    expect(reset.body).toEqual({ success: true });
    expectNoScjwt(reset, cookieName);
    expect((await harness.getWithToken('/me', otpToken)).status).toBe(401);
    const old = await post(harness.createClient(), '/api/auth/sign-in/email', {
      email: userEmail,
      password: OLD_PASSWORD,
    });
    expect(old.status).toBe(401);
    expectNoScjwt(old, cookieName);
    const replacement = await post(
      harness.createClient(),
      '/api/auth/sign-in/email',
      { email: userEmail, password: NEW_PASSWORD },
    );
    expect(replacement.status).toBe(200);
    expectScjwt(replacement, cookieName);
  });

  it('changes email through current and new OTPs while preserving the current sid and another session', async () => {
    const current = harness.createClient();
    const currentSignIn = await post(current, '/api/auth/sign-in/email', {
      email: userEmail,
      password: NEW_PASSWORD,
    });
    const currentToken = expectScjwt(currentSignIn, cookieName);
    const other = harness.createClient();
    const otherSignIn = await post(other, '/api/auth/sign-in/email', {
      email: userEmail,
      password: NEW_PASSWORD,
    });
    const otherToken = expectScjwt(otherSignIn, cookieName);
    const newEmail = `combined-new-${Date.now()}@example.com`;
    await harness.context.internalAdapter.updateUser(userId, {
      emailVerified: false,
    });
    await post(current, '/api/auth/email-otp/send-verification-otp', {
      email: userEmail,
      type: 'email-verification',
    });
    const requested = await post(
      current,
      '/api/auth/email-otp/request-email-change',
      {
        newEmail,
        otp: capture.latest(userEmail, 'email-verification'),
      },
    );
    expect(requested.status).toBe(200);
    const changed = await post(current, '/api/auth/email-otp/change-email', {
      newEmail,
      otp: capture.latest(newEmail, 'change-email'),
    });
    expect(changed.status).toBe(200);
    const replacement = expectScjwt(changed, cookieName);
    expect(sessionIdOf(replacement)).toBe(sessionIdOf(currentToken));
    expect(
      (await current.get('/api/auth/get-session')).body.user,
    ).toMatchObject({ email: newEmail, emailVerified: true });
    expect((await harness.getWithToken('/me', otherToken)).status).toBe(200);
    expect((await other.get('/api/auth/get-session')).body.user).toMatchObject({
      email: newEmail,
      emailVerified: true,
    });
  });
});
