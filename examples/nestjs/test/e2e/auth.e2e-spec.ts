import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import request from 'supertest';

const DATABASE_PATH = resolve('test/.data/native-auth.sqlite');
const ORIGIN = 'http://localhost:3000';
const SECRET = 'nestjs-native-auth-test-secret-at-least-32-bytes';

interface HttpResponse {
  headers: Record<string, string | string[] | undefined>;
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

describe('NestJS Better Auth integration', () => {
  let app: INestApplication;
  let sessionCookieName: string;

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

  it('keeps health anonymous and protects the profile route', async () => {
    await request(app.getHttpServer())
      .get('/health')
      .set('Origin', ORIGIN)
      .expect(200, { status: 'ok' });

    await request(app.getHttpServer())
      .get('/me')
      .set('Origin', ORIGIN)
      .expect(401);
  });

  it('serves the native email/password session lifecycle', async () => {
    const signUp = await request(app.getHttpServer())
      .post('/api/auth/sign-up/email')
      .set('Origin', ORIGIN)
      .send({
        name: 'Nest User',
        email: 'native@example.com',
        password: 'correct-horse-battery-staple',
      })
      .expect(200);
    const cookie = extractCookie(signUp, sessionCookieName);

    await request(app.getHttpServer())
      .get('/me')
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({ email: 'native@example.com' });
        expect(Object.keys(body).sort()).toEqual(['email', 'id']);
      });

    await request(app.getHttpServer())
      .get('/api/auth/get-session')
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .expect(200)
      .expect(({ body }) => {
        expect(body.user.email).toBe('native@example.com');
      });

    await request(app.getHttpServer())
      .post('/api/auth/sign-out')
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .expect(200);

    await request(app.getHttpServer())
      .get('/me')
      .set('Origin', ORIGIN)
      .set('Cookie', cookie)
      .expect(401);
  });
});
