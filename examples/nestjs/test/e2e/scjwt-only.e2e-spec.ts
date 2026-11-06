import {
  createNestAuthHarness,
  expectNoScjwt,
  expectScjwt,
  PASSWORD,
  sessionIdOf,
  type AuthClient,
} from './support/nest-auth-harness.js';

const NEW_PASSWORD = 'correct-horse-battery-staple-updated';

interface ListedSession {
  id: string;
  token: string;
}

describe('NestJS SCJWT-only profile', () => {
  let harness: Awaited<ReturnType<typeof createNestAuthHarness<[]>>>;
  let cookieName: string;

  beforeAll(async () => {
    harness = await createNestAuthHarness({
      name: 'scjwt-only',
      additionalPlugins: [],
    });
    cookieName = harness.sessionCookieName;
  });

  afterAll(async () => {
    await harness?.close();
  });

  /** Signs up through the client's jar and returns the issued SCJWT. */
  async function signUp(client: AuthClient, email: string) {
    const response = await client.post('/api/auth/sign-up/email', {
      name: 'Nest User',
      email,
      password: PASSWORD,
    });
    expect(response.status).toBe(200);
    return expectScjwt(response, cookieName);
  }

  /** Signs in through the client's jar and returns the issued SCJWT. */
  async function signIn(
    client: AuthClient,
    email: string,
    password = PASSWORD,
  ) {
    const response = await client.post('/api/auth/sign-in/email', {
      email,
      password,
    });
    expect(response.status).toBe(200);
    return expectScjwt(response, cookieName);
  }

  it('keeps health anonymous and rejects missing or malformed SCJWTs', async () => {
    const anonymous = harness.createClient();
    expect((await anonymous.get('/health')).body).toEqual({ status: 'ok' });
    expect((await anonymous.get('/me')).status).toBe(401);
    expect(
      (await harness.getWithToken('/me', 'not-a-valid-scjwt')).status,
    ).toBe(401);
  });

  it('authenticates Better Auth and protected Nest routes with an SCJWT', async () => {
    const client = harness.createClient();
    const token = await signUp(client, 'lifecycle@example.com');
    expect(client.token()).toBe(token);

    const session = await client.get('/api/auth/get-session');
    expect(session.status).toBe(200);
    expect(session.body.user.email).toBe('lifecycle@example.com');
    expect(session.body.session.id).toBe(sessionIdOf(token));

    const me = await client.get('/me');
    expect(me.status).toBe(200);
    expect(me.body).toMatchObject({ email: 'lifecycle@example.com' });
    expect(Object.keys(me.body).sort()).toEqual(['email', 'id']);
  });

  it('issues SCJWTs only for valid email and password sign-in', async () => {
    await signUp(harness.createClient(), 'sign-in@example.com');

    const client = harness.createClient();
    const rejected = await client.post('/api/auth/sign-in/email', {
      email: 'sign-in@example.com',
      password: 'incorrect-password',
    });
    expect(rejected.status).toBe(401);
    expectNoScjwt(rejected, cookieName);
    expect(client.token()).toBeUndefined();

    const token = await signIn(client, 'sign-in@example.com');
    expect((await harness.getWithToken('/me', token)).status).toBe(200);
  });

  it('revokes one selected session without terminating the current session', async () => {
    const email = 'revoke-one@example.com';
    const first = await signUp(harness.createClient(), email);
    const current = harness.createClient();
    await signIn(current, email);

    const listed = await current.get('/api/auth/list-sessions');
    expect(listed.status).toBe(200);
    const sessions = listed.body as ListedSession[];
    expect(sessions).toHaveLength(2);
    const firstSession = sessions.find(
      (session) => session.id === sessionIdOf(first),
    );
    expect(firstSession).toBeDefined();

    const revoked = await current.post('/api/auth/revoke-session', {
      token: firstSession?.token,
    });
    expect(revoked.status).toBe(200);
    expectNoScjwt(revoked, cookieName);

    expect((await harness.getWithToken('/me', first)).status).toBe(401);
    expect((await current.get('/me')).status).toBe(200);
  });

  it('revokes every session except the current session', async () => {
    const email = 'revoke-other@example.com';
    const first = await signUp(harness.createClient(), email);
    const current = harness.createClient();
    await signIn(current, email);

    expect((await current.post('/api/auth/revoke-other-sessions')).status).toBe(
      200,
    );

    expect((await harness.getWithToken('/me', first)).status).toBe(401);
    expect((await current.get('/me')).status).toBe(200);
  });

  it('revokes all sessions for the authenticated user', async () => {
    const email = 'revoke-all@example.com';
    const first = await signUp(harness.createClient(), email);
    const current = harness.createClient();
    const currentToken = await signIn(current, email);

    expect((await current.post('/api/auth/revoke-sessions')).status).toBe(200);

    expect((await harness.getWithToken('/me', first)).status).toBe(401);
    expect((await harness.getWithToken('/me', currentToken)).status).toBe(401);
  });

  it('changes the password, re-issues the current session, and revokes the others', async () => {
    const email = 'change-password@example.com';
    const first = await signUp(harness.createClient(), email);
    const current = harness.createClient();
    const currentToken = await signIn(current, email);

    const wrongPassword = await current.post('/api/auth/change-password', {
      currentPassword: 'not-the-password',
      newPassword: NEW_PASSWORD,
      revokeOtherSessions: true,
    });
    expect(wrongPassword.status).toBe(400);
    expectNoScjwt(wrongPassword, cookieName);
    expect((await harness.getWithToken('/me', first)).status).toBe(200);

    const changed = await current.post('/api/auth/change-password', {
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      revokeOtherSessions: true,
    });
    expect(changed.status).toBe(200);
    const replacement = expectScjwt(changed, cookieName);

    expect((await harness.getWithToken('/me', first)).status).toBe(401);
    expect((await harness.getWithToken('/me', currentToken)).status).toBe(401);
    expect((await harness.getWithToken('/me', replacement)).status).toBe(200);
    const oldPassword = await harness
      .createClient()
      .post('/api/auth/sign-in/email', { email, password: PASSWORD });
    expect(oldPassword.status).toBe(401);
    await signIn(harness.createClient(), email, NEW_PASSWORD);
  });

  it('signs out and immediately rejects the revoked SCJWT', async () => {
    const client = harness.createClient();
    const token = await signUp(client, 'sign-out@example.com');

    const signOut = await client.post('/api/auth/sign-out');
    expect(signOut.status).toBe(200);
    expect(client.token()).toBeUndefined();

    expect((await harness.getWithToken('/me', token)).status).toBe(401);
  });
});
