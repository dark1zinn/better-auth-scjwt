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

type UsernamePlugin = ReturnType<typeof username>;
type UsernameHarness = ProfileHarness<[UsernamePlugin]>;

describe('NestJS username profile', () => {
  let harness: UsernameHarness;
  let cookieName: string;

  beforeAll(async () => {
    harness = await createNestAuthHarness({
      name: 'username',
      additionalPlugins: [
        username({
          minUsernameLength: 4,
          maxUsernameLength: 20,
          usernameValidator: (value) => !value.startsWith('admin'),
        }),
      ],
    });
    cookieName = harness.sessionCookieName;
  });

  afterAll(async () => {
    await harness?.close();
  });

  /** Signs up with a username (default `Nest_User`); returns the raw response. */
  async function signUp(
    client: AuthClient,
    email: string,
    value = 'Nest_User',
  ) {
    return client.post('/api/auth/sign-up/email', {
      name: 'Nest User',
      email,
      password: PASSWORD,
      username: value,
    });
  }

  it('normalizes signup usernames while preserving displayUsername and issues a usable SCJWT', async () => {
    const client = harness.createClient();
    const response = await signUp(client, 'username-signup@example.com');

    expect(response.status).toBe(200);
    expect(response.body.user.username).toBe('nest_user');
    expect(response.body.user.displayUsername).toBe('Nest_User');
    const token = expectScjwt(response, cookieName);
    expect(sessionIdOf(token)).toBeTruthy();

    const session = await client.get('/api/auth/get-session');
    expect(session.status).toBe(200);
    expect(session.body.user.username).toBe('nest_user');
    expect(session.body.user.displayUsername).toBe('Nest_User');
    expect((await client.get('/me')).body).toMatchObject({
      email: 'username-signup@example.com',
    });
  });

  it('supports case-insensitive username sign-in and rejects bad credentials without a token', async () => {
    await signUp(
      harness.createClient(),
      'username-login@example.com',
      'Login_User',
    );
    const client = harness.createClient();

    const response = await client.post('/api/auth/sign-in/username', {
      username: 'lOgIn_UsEr',
      password: PASSWORD,
    });
    expect(response.status).toBe(200);
    const token = expectScjwt(response, cookieName);
    expect((await client.get('/api/auth/get-session')).body.user.username).toBe(
      'login_user',
    );
    expect((await harness.getWithToken('/me', token)).status).toBe(200);

    const unknown = await harness
      .createClient()
      .post('/api/auth/sign-in/username', {
        username: 'unknown_user',
        password: PASSWORD,
      });
    expect(unknown.status).toBe(401);
    expect(unknown.body.code).toBe('INVALID_USERNAME_OR_PASSWORD');
    expectNoScjwt(unknown, cookieName);

    const wrong = await harness
      .createClient()
      .post('/api/auth/sign-in/username', {
        username: 'LOGIN_USER',
        password: 'wrong-password',
      });
    expect(wrong.status).toBe(401);
    expect(wrong.body.code).toBe('INVALID_USERNAME_OR_PASSWORD');
    expectNoScjwt(wrong, cookieName);
  });

  it('checks normalized availability and rejects duplicate usernames without creating a user', async () => {
    await signUp(
      harness.createClient(),
      'username-taken@example.com',
      'Taken_User',
    );

    const taken = await harness
      .createClient()
      .post('/api/auth/is-username-available', {
        username: 'TAKEN_USER',
      });
    expect(taken.status).toBe(200);
    expect(taken.body).toEqual({ available: false });

    const free = await harness
      .createClient()
      .post('/api/auth/is-username-available', {
        username: 'free_user',
      });
    expect(free.status).toBe(200);
    expect(free.body).toEqual({ available: true });

    const duplicate = await signUp(
      harness.createClient(),
      'username-duplicate@example.com',
      'taken_user',
    );
    expect(duplicate.status).toBe(400);
    expect(duplicate.body.code).toBe('USERNAME_IS_ALREADY_TAKEN');
    expectNoScjwt(duplicate, cookieName);
    const duplicateLogin = await harness
      .createClient()
      .post('/api/auth/sign-in/email', {
        email: 'username-duplicate@example.com',
        password: PASSWORD,
      });
    expect(duplicateLogin.status).toBe(401);
    expectNoScjwt(duplicateLogin, cookieName);
  });

  it('rejects short, long, and custom-invalid usernames without issuing SCJWTs', async () => {
    const cases = [
      ['short', 'abc', 'USERNAME_TOO_SHORT'],
      ['long', 'a'.repeat(21), 'USERNAME_TOO_LONG'],
      ['custom', 'administrator', 'INVALID_USERNAME'],
    ] as const;
    for (const [label, value, code] of cases) {
      const response = await signUp(
        harness.createClient(),
        `username-${label}@example.com`,
        value,
      );
      expect(response.status).toBe(400);
      expect(response.body.code).toBe(code);
      expectNoScjwt(response, cookieName);
    }
  });

  it('updates the username over HTTP and keeps the existing session usable', async () => {
    const client = harness.createClient();
    const token = expectScjwt(
      await signUp(client, 'username-update@example.com', 'Original_User'),
      cookieName,
    );
    const updated = await client.post('/api/auth/update-user', {
      username: 'Updated_User',
    });
    expect(updated.status).toBe(200);
    const setCookie = updated.headers['set-cookie'];
    const replacement =
      Array.isArray(setCookie) &&
      setCookie.some((cookie) => cookie.startsWith(`${cookieName}=`));
    if (replacement) {
      expect(sessionIdOf(expectScjwt(updated, cookieName))).toBe(
        sessionIdOf(token),
      );
    } else {
      expectNoScjwt(updated, cookieName);
    }
    const session = await client.get('/api/auth/get-session');
    expect(session.status).toBe(200);
    expect(session.body.user.username).toBe('updated_user');
    expect(session.body.session.id).toBe(sessionIdOf(token));
    expect((await client.get('/me')).status).toBe(200);
  });
});

describe('NestJS immutable username profile', () => {
  let harness: UsernameHarness;
  let cookieName: string;

  beforeAll(async () => {
    harness = await createNestAuthHarness({
      name: 'username-immutable',
      additionalPlugins: [username({ immutableUsername: true })],
    });
    cookieName = harness.sessionCookieName;
  });

  afterAll(async () => {
    await harness?.close();
  });

  it('allows initial assignment and same normalized username, then rejects changes', async () => {
    const first = harness.createClient();
    const signup = await first.post('/api/auth/sign-up/email', {
      name: 'Immutable User',
      email: 'immutable-first@example.com',
      password: PASSWORD,
    });
    expect(signup.status).toBe(200);
    const token = expectScjwt(signup, cookieName);

    const initial = await first.post('/api/auth/update-user', {
      username: 'Immutable_User',
    });
    expect(initial.status).toBe(200);
    expect((await first.get('/api/auth/get-session')).body.user.username).toBe(
      'immutable_user',
    );

    const same = await first.post('/api/auth/update-user', {
      username: 'IMMUTABLE_USER',
    });
    expect(same.status).toBe(200);
    const sameCookie = same.headers['set-cookie'];
    if (
      Array.isArray(sameCookie) &&
      sameCookie.some((cookie) => cookie.startsWith(`${cookieName}=`))
    ) {
      expect(sessionIdOf(expectScjwt(same, cookieName))).toBe(
        sessionIdOf(token),
      );
    } else {
      expectNoScjwt(same, cookieName);
    }

    const changed = await first.post('/api/auth/update-user', {
      username: 'Different_User',
    });
    expect(changed.status).toBe(400);
    expect(changed.body.code).toBe('USERNAME_IS_IMMUTABLE');
    expectNoScjwt(changed, cookieName);
    expect((await first.get('/api/auth/get-session')).body.user.username).toBe(
      'immutable_user',
    );
    expect((await harness.getWithToken('/me', token)).status).toBe(200);
  });

  it('requires the owning SCJWT before immutable username updates', async () => {
    const owner = harness.createClient();
    const ownerSignup = await owner.post('/api/auth/sign-up/email', {
      name: 'Owner',
      email: 'immutable-owner@example.com',
      password: PASSWORD,
      username: 'Owner_User',
    });
    expect(ownerSignup.status).toBe(200);
    const ownerToken = expectScjwt(ownerSignup, cookieName);

    const anonymous = harness.createClient();
    const noToken = await anonymous.post('/api/auth/update-user', {
      username: 'No_Token',
    });
    expect(noToken.status).toBe(401);
    expectNoScjwt(noToken, cookieName);

    const other = harness.createClient();
    const otherSignup = await other.post('/api/auth/sign-up/email', {
      name: 'Other',
      email: 'immutable-other@example.com',
      password: PASSWORD,
      username: 'Other_User',
    });
    expect(otherSignup.status).toBe(200);
    const otherToken = expectScjwt(otherSignup, cookieName);
    const forbidden = await harness.postWithToken(
      '/api/auth/update-user',
      otherToken,
      {
        username: 'Owner_User',
      },
    );
    expect(forbidden.status).toBe(400);
    expect(forbidden.body.code).toBe('USERNAME_IS_IMMUTABLE');
    expectNoScjwt(forbidden, cookieName);
    expect(
      (await harness.getWithToken('/api/auth/get-session', ownerToken)).body
        .user.username,
    ).toBe('owner_user');
  });
});
