import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { decodeJwt } from 'jose';
import request from 'supertest';

const DATABASE_PATH = resolve('test/.data/scjwt-auth.sqlite');
const ORIGIN = 'http://localhost:3000';
const SECRET = 'nestjs-scjwt-test-secret-at-least-32-bytes';
const PASSWORD = 'correct-horse-battery-staple';
const NEW_PASSWORD = 'correct-horse-battery-staple-updated';
const FINGERPRINT_HEADERS = {
  Host: 'localhost:3000',
  Origin: ORIGIN,
  'User-Agent': 'better-auth-scjwt-nestjs-e2e',
  'Sec-CH-UA-Platform': '"Linux"',
} as const;

interface HttpResponse {
  headers: Record<string, string | string[] | undefined>;
}

interface ListedSession {
  id: string;
  token: string;
}

function extractCookie(response: HttpResponse, cookieName: string): string {
  const values = response.headers['set-cookie'];
  const setCookies = Array.isArray(values) ? values : values ? [values] : [];
  const cookie = setCookies
    .find((value) => value.startsWith(`${cookieName}=`))
    ?.split(';', 1)[0];
  if (!cookie) {
    throw new Error(`Response did not set ${cookieName}.`);
  }
  return cookie;
}

function cookieValue(cookie: string): string {
  const separator = cookie.indexOf('=');
  if (separator === -1) {
    throw new Error('Cookie does not contain a value.');
  }
  return decodeURIComponent(cookie.slice(separator + 1));
}

function sessionId(cookie: string): string {
  const sid = decodeJwt(cookieValue(cookie)).sid;
  if (typeof sid !== 'string') {
    throw new Error('SCJWT does not contain a session id.');
  }
  return sid;
}

describe('NestJS SCJWT integration', () => {
  let app: INestApplication;
  let sessionCookieName: string;

  function get(path: string) {
    return request(app.getHttpServer()).get(path).set(FINGERPRINT_HEADERS);
  }

  function post(path: string) {
    return request(app.getHttpServer()).post(path).set(FINGERPRINT_HEADERS);
  }

  async function signUp(email: string, password = PASSWORD) {
    const response = await post('/api/auth/sign-up/email')
      .send({ name: 'Nest User', email, password })
      .expect(200);
    const cookie = extractCookie(response, sessionCookieName);
    expect(cookieValue(cookie).split('.')).toHaveLength(3);
    return cookie;
  }

  async function signIn(email: string, password = PASSWORD) {
    const response = await post('/api/auth/sign-in/email')
      .send({ email, password })
      .expect(200);
    const cookie = extractCookie(response, sessionCookieName);
    expect(cookieValue(cookie).split('.')).toHaveLength(3);
    return cookie;
  }

  beforeAll(async () => {
    rmSync(DATABASE_PATH, { force: true });
    mkdirSync(dirname(DATABASE_PATH), { recursive: true });
    process.env.BETTER_AUTH_DATABASE = DATABASE_PATH;
    process.env.BETTER_AUTH_SECRET = SECRET;
    process.env.BETTER_AUTH_URL = ORIGIN;

    const [{ AppModule }, { auth }] = await Promise.all([
      import('../../src/app.module.js'),
      import('../../src/auth.js'),
    ]);
    const context = await auth.$context;
    await context.runMigrations();
    sessionCookieName = context.authCookies.sessionToken.name;

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleRef.createNestApplication({ bodyParser: false });
    await app.init();
  });

  afterAll(async () => {
    await app.close();
    for (const suffix of ['', '-shm', '-wal']) {
      rmSync(`${DATABASE_PATH}${suffix}`, { force: true });
    }
  });

  it('keeps health anonymous and rejects missing or malformed SCJWTs', async () => {
    await get('/health').expect(200, { status: 'ok' });
    await get('/me').expect(401);
    await get('/me')
      .set('Cookie', `${sessionCookieName}=not-a-valid-scjwt`)
      .expect(401);
  });

  it('authenticates Better Auth and protected Nest routes with an SCJWT', async () => {
    const cookie = await signUp('lifecycle@example.com');

    await get('/api/auth/get-session')
      .set('Cookie', cookie)
      .expect(200)
      .expect(({ body }) => {
        expect(body.user.email).toBe('lifecycle@example.com');
      });

    await get('/me')
      .set('Cookie', cookie)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({ email: 'lifecycle@example.com' });
        expect(Object.keys(body).sort()).toEqual(['email', 'id']);
      });
  });

  it('issues SCJWTs only for valid email and password sign-in', async () => {
    await signUp('sign-in@example.com');

    await post('/api/auth/sign-in/email')
      .send({ email: 'sign-in@example.com', password: 'incorrect-password' })
      .expect(401);

    const cookie = await signIn('sign-in@example.com');
    await get('/me').set('Cookie', cookie).expect(200);
  });

  it('revokes one selected session without terminating the current session', async () => {
    const email = 'revoke-one@example.com';
    const firstCookie = await signUp(email);
    const currentCookie = await signIn(email);

    const response = await get('/api/auth/list-sessions')
      .set('Cookie', currentCookie)
      .expect(200);
    const sessions = response.body as ListedSession[];
    expect(sessions).toHaveLength(2);
    const firstSession = sessions.find(
      (session) => session.id === sessionId(firstCookie),
    );
    if (!firstSession) {
      throw new Error('The first session was not returned by list-sessions.');
    }

    await post('/api/auth/revoke-session')
      .set('Cookie', currentCookie)
      .send({ token: firstSession.token })
      .expect(200);

    await get('/me').set('Cookie', firstCookie).expect(401);
    await get('/me').set('Cookie', currentCookie).expect(200);
  });

  it('revokes every session except the current session', async () => {
    const email = 'revoke-other@example.com';
    const firstCookie = await signUp(email);
    const currentCookie = await signIn(email);

    await post('/api/auth/revoke-other-sessions')
      .set('Cookie', currentCookie)
      .send({})
      .expect(200);

    await get('/me').set('Cookie', firstCookie).expect(401);
    await get('/me').set('Cookie', currentCookie).expect(200);
  });

  it('revokes all sessions for the authenticated user', async () => {
    const email = 'revoke-all@example.com';
    const firstCookie = await signUp(email);
    const currentCookie = await signIn(email);

    await post('/api/auth/revoke-sessions')
      .set('Cookie', currentCookie)
      .send({})
      .expect(200);

    await get('/me').set('Cookie', firstCookie).expect(401);
    await get('/me').set('Cookie', currentCookie).expect(401);
  });

  it('changes the password and revokes other sessions', async () => {
    const email = 'change-password@example.com';
    const firstCookie = await signUp(email);
    const currentCookie = await signIn(email);

    const changePassword = await post('/api/auth/change-password')
      .set('Cookie', currentCookie)
      .send({
        currentPassword: PASSWORD,
        newPassword: NEW_PASSWORD,
        revokeOtherSessions: true,
      })
      .expect(200);
    const replacementCookie = extractCookie(changePassword, sessionCookieName);
    expect(cookieValue(replacementCookie).split('.')).toHaveLength(3);

    await get('/me').set('Cookie', firstCookie).expect(401);
    await get('/me').set('Cookie', currentCookie).expect(401);
    await get('/me').set('Cookie', replacementCookie).expect(200);
    await post('/api/auth/sign-in/email')
      .send({ email, password: PASSWORD })
      .expect(401);
    const newCookie = await signIn(email, NEW_PASSWORD);
    await get('/me').set('Cookie', newCookie).expect(200);
  });

  it('signs out and immediately rejects the revoked SCJWT', async () => {
    const cookie = await signUp('sign-out@example.com');

    await post('/api/auth/sign-out').set('Cookie', cookie).send({}).expect(200);

    await get('/me').set('Cookie', cookie).expect(401);
  });
});
