import { captcha } from 'better-auth/plugins/captcha';
import {
  CAPTCHA_ERROR,
  CAPTCHA_PASS,
  CAPTCHA_REJECT,
  CAPTCHA_SECRET,
  captchaHeaders,
  startCaptchaVerifier,
  type CaptchaVerifier,
} from './support/plugin-fixtures.js';
import {
  createNestAuthHarness,
  expectNoScjwt,
  expectScjwt,
  PASSWORD,
  type AuthClient,
} from './support/nest-auth-harness.js';

describe('NestJS captcha profile', () => {
  let verifier: CaptchaVerifier;
  let harness: Awaited<
    ReturnType<typeof createNestAuthHarness<[ReturnType<typeof captcha>]>>
  >;
  let cookieName: string;

  beforeAll(async () => {
    verifier = startCaptchaVerifier();
    harness = await createNestAuthHarness({
      name: 'captcha',
      additionalPlugins: [
        captcha({
          provider: 'cloudflare-turnstile',
          secretKey: CAPTCHA_SECRET,
          siteVerifyURLOverride: verifier.url,
          endpoints: [
            '/sign-up/email',
            '/sign-in/email',
            '/request-password-reset',
          ],
        }),
      ],
      emailAndPassword: { sendResetPassword: async () => {} },
      dispose: [verifier.stop],
    });
    cookieName = harness.sessionCookieName;
  });

  afterAll(async () => {
    await harness?.close();
  });

  /** POSTs with an `x-captcha-response` header when a captcha value is given. */
  async function post(
    client: AuthClient,
    path: string,
    body: object,
    response?: string,
  ) {
    return client.post(path, body, response ? captchaHeaders(response) : {});
  }

  /**
   * Asserts a captcha-protected request fails with the given status/code,
   * emits no SCJWT, and leaves no new user (or no session for an existing one).
   */
  async function expectCaptchaFailure(
    path: string,
    email: string,
    expectedStatus: number,
    expectedCode: string,
    response?: string,
    userMustBeAbsent = true,
  ) {
    const client = harness.createClient();
    const result = await post(
      client,
      path,
      path === '/api/auth/request-password-reset'
        ? { email }
        : { name: 'Captcha User', email, password: PASSWORD },
      response,
    );
    expect(result.status).toBe(expectedStatus);
    expect(result.body.code).toBe(expectedCode);
    expectNoScjwt(result, cookieName);
    expect(client.token()).toBeUndefined();
    const user = await harness.context.internalAdapter.findUserByEmail(email);
    if (userMustBeAbsent) {
      expect(user).toBeNull();
    } else {
      expect(user).not.toBeNull();
      if (user) {
        expect(
          await harness.context.internalAdapter.listSessions(user.user.id),
        ).toHaveLength(0);
      }
    }
  }

  it('rejects missing, failed, and unavailable captcha responses before mutations', async () => {
    await expectCaptchaFailure(
      '/api/auth/sign-up/email',
      'captcha-missing@example.com',
      400,
      'MISSING_RESPONSE',
    );
    await expectCaptchaFailure(
      '/api/auth/sign-up/email',
      'captcha-rejected@example.com',
      403,
      'VERIFICATION_FAILED',
      CAPTCHA_REJECT,
    );
    await expectCaptchaFailure(
      '/api/auth/sign-up/email',
      'captcha-error@example.com',
      500,
      'UNKNOWN_ERROR',
      CAPTCHA_ERROR,
    );

    const signInEmail = 'captcha-sign-in@example.com';
    const setup = harness.createClient();
    const setupResponse = await post(
      setup,
      '/api/auth/sign-up/email',
      { name: 'Captcha Sign In', email: signInEmail, password: PASSWORD },
      CAPTCHA_PASS,
    );
    expect(setupResponse.status).toBe(200);
    expectScjwt(setupResponse, cookieName);
    await setup.post('/api/auth/sign-out');

    await expectCaptchaFailure(
      '/api/auth/sign-in/email',
      signInEmail,
      400,
      'MISSING_RESPONSE',
      undefined,
      false,
    );
    await expectCaptchaFailure(
      '/api/auth/sign-in/email',
      signInEmail,
      403,
      'VERIFICATION_FAILED',
      CAPTCHA_REJECT,
      false,
    );
    await expectCaptchaFailure(
      '/api/auth/sign-in/email',
      signInEmail,
      500,
      'UNKNOWN_ERROR',
      CAPTCHA_ERROR,
      false,
    );

    await expectCaptchaFailure(
      '/api/auth/request-password-reset',
      'captcha-reset-missing@example.com',
      400,
      'MISSING_RESPONSE',
    );

    await expectCaptchaFailure(
      '/api/auth/request-password-reset',
      'captcha-reset-rejected@example.com',
      403,
      'VERIFICATION_FAILED',
      CAPTCHA_REJECT,
    );
    await expectCaptchaFailure(
      '/api/auth/request-password-reset',
      'captcha-reset-error@example.com',
      500,
      'UNKNOWN_ERROR',
      CAPTCHA_ERROR,
    );

    expect(verifier.requests).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          secret: CAPTCHA_SECRET,
          response: CAPTCHA_REJECT,
        }),
        expect.objectContaining({
          secret: CAPTCHA_SECRET,
          response: CAPTCHA_ERROR,
        }),
      ]),
    );
  });

  it('issues usable SCJWTs for accepted sign-up and sign-in, and protects reset', async () => {
    const email = 'captcha-accepted@example.com';
    const signupClient = harness.createClient();
    const signup = await post(
      signupClient,
      '/api/auth/sign-up/email',
      { name: 'Accepted Captcha', email, password: PASSWORD },
      CAPTCHA_PASS,
    );
    expect(signup.status).toBe(200);
    const signupToken = expectScjwt(signup, cookieName);
    expect((await signupClient.get('/me')).status).toBe(200);
    expect((await signupClient.get('/api/auth/get-session')).status).toBe(200);

    await signupClient.post('/api/auth/sign-out');
    const signinClient = harness.createClient();
    const signin = await post(
      signinClient,
      '/api/auth/sign-in/email',
      { email, password: PASSWORD },
      CAPTCHA_PASS,
    );
    expect(signin.status).toBe(200);
    const signinToken = expectScjwt(signin, cookieName);
    expect(signinToken).not.toBe(signupToken);
    expect((await signinClient.get('/me')).status).toBe(200);
    expect((await signinClient.get('/api/auth/get-session')).status).toBe(200);

    const reset = await post(
      harness.createClient(),
      '/api/auth/request-password-reset',
      { email },
      CAPTCHA_PASS,
    );
    expect(reset.status).toBe(200);
    expectNoScjwt(reset, cookieName);

    const before = verifier.requests.length;
    const session = await signinClient.get('/api/auth/get-session');
    expect(session.status).toBe(200);
    expect(verifier.requests.length).toBe(before);
  });
});
