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

/** A freshly signed-up account owned by a single test case. */
interface UserFixture {
  client: AuthClient;
  token: string;
  user: UserRecord;
  email: string;
}

/** A freshly promoted administrator owned by a single test case. */
interface AdminFixture {
  client: AuthClient;
  id: string;
}

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
const NEW_PASSWORD = 'combined-reset-password-123';

type CombinedPlugins = [
  ReturnType<typeof admin>,
  ReturnType<typeof captcha>,
  ReturnType<typeof username>,
  ReturnType<typeof emailOTP>,
  ReturnType<typeof i18n>,
];

/**
 * Every case creates the accounts, roles, verification state and clients it
 * uses, so each `it` passes alone (`-t`) and in any order. Only the Nest
 * application, captcha verifier and OTP outbox are shared.
 */
describe('NestJS combined-plugins profile', () => {
  let verifier: CaptchaVerifier;
  let harness: ProfileHarness<CombinedPlugins>;
  let cookieName: string;
  let sequence = 0;
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

  function uniqueEmail(label: string): string {
    sequence += 1;
    return `combined-${label}-${sequence}@example.com`;
  }

  async function signUpUser(
    label: string,
    extra: Record<string, string> = {},
  ): Promise<UserFixture> {
    const client = harness.createClient();
    const email = uniqueEmail(label);
    const signup = await post(client, '/api/auth/sign-up/email', {
      name: `Combined ${label}`,
      email,
      password: PASSWORD,
      ...extra,
    });
    expect(signup.status).toBe(200);
    return {
      client,
      token: expectScjwt(signup, cookieName),
      user: signup.body.user as UserRecord,
      email,
    };
  }

  async function createAdmin(label: string): Promise<AdminFixture> {
    const fixture = await signUpUser(`${label}-admin`);
    await harness.context.internalAdapter.updateUser(fixture.user.id, {
      role: 'admin',
    });
    expect((await fixture.client.get('/me')).status).toBe(200);
    return { client: fixture.client, id: fixture.user.id };
  }

  async function signIn(email: string, password = PASSWORD) {
    const client = harness.createClient();
    const response = await post(client, '/api/auth/sign-in/email', {
      email,
      password,
    });
    expect(response.status).toBe(200);
    return { client, token: expectScjwt(response, cookieName) };
  }

  /** Proves email ownership through the real email-OTP verification flow. */
  async function verifyEmail(client: AuthClient, email: string) {
    const sent = await post(
      client,
      '/api/auth/email-otp/send-verification-otp',
      { email, type: 'email-verification' },
    );
    expect(sent.status).toBe(200);
    const verified = await post(client, '/api/auth/email-otp/verify-email', {
      email,
      otp: capture.latest(email, 'email-verification'),
    });
    expect(verified.status).toBe(200);
    expectNoScjwt(verified, cookieName);
  }

  it('signs up with captcha, username, locale, and default Admin role', async () => {
    const absentEmail = uniqueEmail('no-captcha');
    const absent = await harness
      .createClient()
      .post('/api/auth/sign-up/email', {
        name: 'No Captcha',
        email: absentEmail,
        password: PASSWORD,
        username: 'no_captcha',
        locale: 'fr',
      });
    expect(absent.status).toBe(400);
    expect(absent.body.code).toBe('MISSING_RESPONSE');
    expectNoScjwt(absent, cookieName);
    expect(
      await harness.context.internalAdapter.findUserByEmail(absentEmail),
    ).toBeNull();

    const { client, user, email } = await signUpUser('signup', {
      username: 'Signup_User',
      locale: 'fr',
    });
    expect(user).toMatchObject({
      role: 'user',
      username: 'signup_user',
      locale: 'fr',
    });
    const session = await client.get('/api/auth/get-session');
    expect(session.status).toBe(200);
    expect(session.body.user).toMatchObject({
      role: 'user',
      username: 'signup_user',
      locale: 'fr',
    });
    expect((await client.get('/me')).body).toEqual({ id: user.id, email });
  });

  it('authenticates username and email OTP sessions, while captcha gates OTP delivery', async () => {
    const owner = await signUpUser('otp', {
      username: 'Otp_User',
      locale: 'fr',
    });
    const usernameClient = harness.createClient();
    const usernameSignin = await post(
      usernameClient,
      '/api/auth/sign-in/username',
      { username: 'OTP_USER', password: PASSWORD },
    );
    expect(usernameSignin.status).toBe(200);
    const usernameToken = expectScjwt(usernameSignin, cookieName);
    expect(sessionIdOf(usernameToken)).not.toBe(sessionIdOf(owner.token));
    expect(
      (await usernameClient.get('/api/auth/get-session')).body.user.username,
    ).toBe('otp_user');
    expect((await usernameClient.get('/me')).status).toBe(200);

    const otpClient = harness.createClient();
    const before = capture.count(owner.email, 'sign-in');
    const rejected = await post(
      otpClient,
      '/api/auth/email-otp/send-verification-otp',
      { email: owner.email, type: 'sign-in' },
      CAPTCHA_REJECT,
    );
    expect(rejected.status).toBe(403);
    expect(rejected.body.code).toBe('VERIFICATION_FAILED');
    expectNoScjwt(rejected, cookieName);
    expect(capture.count(owner.email, 'sign-in')).toBe(before);

    await verifyEmail(otpClient, owner.email);
    const sent = await post(
      otpClient,
      '/api/auth/email-otp/send-verification-otp',
      { email: owner.email, type: 'sign-in' },
    );
    expect(sent.status).toBe(200);

    const unproven = await signUpUser('unproven');
    await harness.context.internalAdapter.updateUser(unproven.user.id, {
      emailVerified: false,
    });
    const unprovenSend = await post(
      harness.createClient(),
      '/api/auth/email-otp/send-verification-otp',
      { email: unproven.email, type: 'sign-in' },
    );
    expect(unprovenSend.status).toBe(200);
    const unprovenSignin = await post(
      harness.createClient(),
      '/api/auth/sign-in/email-otp',
      {
        email: unproven.email,
        otp: capture.latest(unproven.email, 'sign-in'),
      },
    );
    expect(unprovenSignin.status).toBe(200);
    expectScjwt(unprovenSignin, cookieName);
    expect((await harness.getWithToken('/me', unproven.token)).status).toBe(
      401,
    );

    const otpSignin = await post(otpClient, '/api/auth/sign-in/email-otp', {
      email: owner.email,
      otp: capture.latest(owner.email, 'sign-in'),
    });
    expect(otpSignin.status).toBe(200);
    const otpToken = expectScjwt(otpSignin, cookieName);
    expect(sessionIdOf(otpToken)).not.toBe(sessionIdOf(usernameToken));
    expect(
      (await otpClient.get('/api/auth/get-session')).body.user,
    ).toMatchObject({ username: 'otp_user', locale: 'fr' });
    expect((await otpClient.get('/me')).status).toBe(200);
  });

  it('localizes valid-captcha credential errors and rejects captcha before authentication', async () => {
    const { email } = await signUpUser('localized');
    const wrong = await harness
      .createClient()
      .post(
        '/api/auth/sign-in/email',
        { email, password: 'wrong-password' },
        { ...captchaHeaders(CAPTCHA_PASS), 'Accept-Language': 'fr' },
      );
    expect(wrong.status).toBe(401);
    expect(wrong.body.code).toBe('INVALID_EMAIL_OR_PASSWORD');
    expect(wrong.body.message).toBe(
      FRENCH_TRANSLATIONS.INVALID_EMAIL_OR_PASSWORD,
    );
    expectNoScjwt(wrong, cookieName);

    const rejected = await harness
      .createClient()
      .post(
        '/api/auth/sign-in/email',
        { email, password: 'wrong-password' },
        { ...captchaHeaders(CAPTCHA_REJECT), 'Accept-Language': 'fr' },
      );
    expect(rejected.status).toBe(403);
    expect(rejected.body.code).toBe('VERIFICATION_FAILED');
    expectNoScjwt(rejected, cookieName);
  });

  it('updates RBAC through HTTP and enforces captcha and authorization', async () => {
    const administrator = await createAdmin('rbac');
    const member = await signUpUser('rbac');
    const missing = await administrator.client.post(
      '/api/auth/admin/set-role',
      { userId: member.user.id, role: 'auditor' },
    );
    expect(missing.status).toBe(400);
    expect(missing.body.code).toBe('MISSING_RESPONSE');
    const changed = await post(administrator.client, '/api/auth/admin/set-role', {
      userId: member.user.id,
      role: 'auditor',
    });
    expect(changed.status).toBe(200);
    expectNoScjwt(changed, cookieName);
    const memberSession = await member.client.get('/api/auth/get-session');
    expect(memberSession.status).toBe(200);
    expect(memberSession.body.user.role).toBe('auditor');
    const read = await post(member.client, '/api/auth/admin/has-permission', {
      permissions: { project: ['read'] },
    });
    expect(read.status).toBe(200);
    expect(read.body).toEqual({ error: null, success: true });
    const create = await post(member.client, '/api/auth/admin/has-permission', {
      permissions: { project: ['create'] },
    });
    expect(create.body).toEqual({ error: null, success: false });
    const denied = await post(member.client, '/api/auth/admin/ban-user', {
      userId: administrator.id,
    });
    expect(denied.status).toBe(403);
    expectNoScjwt(denied, cookieName);
  });

  it('impersonates and restores the original administrator session', async () => {
    const administrator = await createAdmin('impersonation');
    const target = await signUpUser('impersonated');
    const original = administrator.client.token();
    expect(original).toBeDefined();
    const impersonated = await post(
      administrator.client,
      '/api/auth/admin/impersonate-user',
      { userId: target.user.id },
    );
    expect(impersonated.status).toBe(200);
    const impersonationToken = expectScjwt(impersonated, cookieName);
    expect(
      (await administrator.client.get('/api/auth/get-session')).body.session
        .impersonatedBy,
    ).toBe(administrator.id);
    const stopped = await post(
      administrator.client,
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
    const administrator = await createAdmin('ban');
    const target = await signUpUser('banned');
    const second = await signIn(target.email);
    const listed = await post(
      administrator.client,
      '/api/auth/admin/list-user-sessions',
      { userId: target.user.id },
    );
    expect(listed.status).toBe(200);
    const sessions = listed.body.sessions as SessionRecord[];
    const selected = sessions.find(
      (session) => session.id === sessionIdOf(target.token),
    );
    expect(selected).toBeDefined();
    const revoked = await post(
      administrator.client,
      '/api/auth/admin/revoke-user-session',
      { sessionToken: selected?.token },
    );
    expect(revoked.status).toBe(200);
    expect((await harness.getWithToken('/me', target.token)).status).toBe(401);
    expect((await harness.getWithToken('/me', second.token)).status).toBe(200);
    const banned = await post(administrator.client, '/api/auth/admin/ban-user', {
      userId: target.user.id,
      banReason: 'combined test',
    });
    expect(banned.status).toBe(200);
    expect((await harness.getWithToken('/me', second.token)).status).toBe(401);
    const unbanned = await post(
      administrator.client,
      '/api/auth/admin/unban-user',
      { userId: target.user.id },
    );
    expect(unbanned.status).toBe(200);
    expect((await harness.getWithToken('/me', second.token)).status).toBe(401);
  });

  it('resets the password, revokes pre-reset sessions, and signs in with the replacement password', async () => {
    const owner = await signUpUser('reset');
    const liveTokens = [owner.token, (await signIn(owner.email)).token];
    for (const token of liveTokens) {
      expect((await harness.getWithToken('/me', token)).status).toBe(200);
    }
    const request = await post(
      harness.createClient(),
      '/api/auth/email-otp/request-password-reset',
      { email: owner.email },
    );
    expect(request.status).toBe(200);
    const reset = await post(
      harness.createClient(),
      '/api/auth/email-otp/reset-password',
      {
        email: owner.email,
        otp: capture.latest(owner.email, 'forget-password'),
        password: NEW_PASSWORD,
      },
    );
    expect(reset.status).toBe(200);
    expect(reset.body).toEqual({ success: true });
    expectNoScjwt(reset, cookieName);
    for (const token of liveTokens) {
      expect((await harness.getWithToken('/me', token)).status).toBe(401);
    }
    const old = await post(harness.createClient(), '/api/auth/sign-in/email', {
      email: owner.email,
      password: PASSWORD,
    });
    expect(old.status).toBe(401);
    expectNoScjwt(old, cookieName);
    await signIn(owner.email, NEW_PASSWORD);
  });

  it('changes email through current and new OTPs while preserving the current sid and another session', async () => {
    const owner = await signUpUser('email-change');
    const current = await signIn(owner.email);
    const other = await signIn(owner.email);
    const newEmail = uniqueEmail('email-changed');
    await harness.context.internalAdapter.updateUser(owner.user.id, {
      emailVerified: false,
    });
    await post(current.client, '/api/auth/email-otp/send-verification-otp', {
      email: owner.email,
      type: 'email-verification',
    });
    const requested = await post(
      current.client,
      '/api/auth/email-otp/request-email-change',
      {
        newEmail,
        otp: capture.latest(owner.email, 'email-verification'),
      },
    );
    expect(requested.status).toBe(200);
    const changed = await post(
      current.client,
      '/api/auth/email-otp/change-email',
      { newEmail, otp: capture.latest(newEmail, 'change-email') },
    );
    expect(changed.status).toBe(200);
    const replacement = expectScjwt(changed, cookieName);
    expect(sessionIdOf(replacement)).toBe(sessionIdOf(current.token));
    expect(
      (await current.client.get('/api/auth/get-session')).body.user,
    ).toMatchObject({ email: newEmail, emailVerified: true });
    expect((await harness.getWithToken('/me', other.token)).status).toBe(200);
    expect(
      (await other.client.get('/api/auth/get-session')).body.user,
    ).toMatchObject({ email: newEmail, emailVerified: true });
  });
});
