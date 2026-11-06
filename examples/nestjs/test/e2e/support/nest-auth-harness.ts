import type { INestApplication } from '@nestjs/common';
import { Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { AuthContext, BetterAuthPlugin } from 'better-auth';
import { rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { decodeJwt } from 'jose';
import request from 'supertest';
import { createAppModuleMetadata } from '../../../src/app-module.metadata.js';
import {
  createAuth,
  type CreateAuthOptions,
} from '../../../src/auth.factory.js';

export const ORIGIN = 'http://localhost:3000';
export const SECRET = 'nestjs-scjwt-test-secret-at-least-32-bytes';
export const PASSWORD = 'correct-horse-battery-staple';
export const FINGERPRINT_HEADERS = {
  Host: 'localhost:3000',
  Origin: ORIGIN,
  'User-Agent': 'better-auth-scjwt-nestjs-e2e',
  'Sec-CH-UA-Platform': '"Linux"',
} as const;

type HeaderMap = Record<string, string>;

export type HttpResponse = request.Response;

export interface NestAuthProfile<
  AdditionalPlugins extends BetterAuthPlugin[],
> extends Omit<
  CreateAuthOptions<AdditionalPlugins>,
  'databasePath' | 'baseURL' | 'secret'
> {
  /** Unique per spec file; names the isolated SQLite database. */
  name: string;
  /** Local fixture services (captcha verifier, …) stopped on close. */
  dispose?: Array<() => void | Promise<void>>;
}

export interface AuthClient {
  get(path: string, headers?: HeaderMap): Promise<HttpResponse>;
  post(path: string, body?: object, headers?: HeaderMap): Promise<HttpResponse>;
  /** Raw (still URL-encoded) cookie value held by this client's jar. */
  cookie(name: string): string | undefined;
  /** Decoded SCJWT currently held by this client's jar. */
  token(): string | undefined;
}

export type HarnessContext = Pick<
  AuthContext,
  'internalAdapter' | 'authCookies'
>;

export interface NestAuthHarness<Auth> {
  app: INestApplication;
  auth: Auth;
  /** Setup-only access to Better Auth internals (promoting fixture admins, …). */
  context: HarnessContext;
  sessionCookieName: string;
  /** New client with its own Supertest agent and cookie jar. */
  createClient(): AuthClient;
  /** Stateless request presenting exactly the given SCJWT (no jar). */
  getWithToken(
    path: string,
    token: string,
    headers?: HeaderMap,
  ): Promise<HttpResponse>;
  postWithToken(
    path: string,
    token: string,
    body?: object,
    headers?: HeaderMap,
  ): Promise<HttpResponse>;
  close(): Promise<void>;
}

export type ProfileHarness<AdditionalPlugins extends BetterAuthPlugin[]> =
  NestAuthHarness<ReturnType<typeof createAuth<AdditionalPlugins>>>;

/**
 * Boots an isolated Nest application for one plugin profile: a fresh SQLite
 * file, Better Auth migrations, and per-client cookie jars. `close()` is
 * idempotent and removes the database files.
 */
export async function createNestAuthHarness<
  const AdditionalPlugins extends BetterAuthPlugin[],
>(
  profile: NestAuthProfile<AdditionalPlugins>,
): Promise<ProfileHarness<AdditionalPlugins>> {
  const databasePath = resolve(`test/.data/${profile.name}.sqlite`);
  removeDatabase(databasePath);
  const { name: _name, dispose = [], ...authOptions } = profile;
  const auth = createAuth({
    ...authOptions,
    databasePath,
    baseURL: ORIGIN,
    secret: SECRET,
  });
  const context = await auth.$context;
  await context.runMigrations();
  const sessionCookieName = context.authCookies.sessionToken.name;

  @Module(createAppModuleMetadata(auth))
  class ProfileAppModule {}

  const moduleRef = await Test.createTestingModule({
    imports: [ProfileAppModule],
  }).compile();
  const app = moduleRef.createNestApplication({ bodyParser: false });
  await app.init();
  const server = app.getHttpServer();

  let closed = false;
  const harness: ProfileHarness<AdditionalPlugins> = {
    app,
    auth,
    context,
    sessionCookieName,
    createClient() {
      const agent = request.agent(server);
      const cookie = (name: string) =>
        agent.jar.getCookie(name, {
          domain: '127.0.0.1',
          path: '/',
          secure: false,
          script: false,
        })?.value;
      return {
        get: (path, headers = {}) =>
          agent.get(path).set({ ...FINGERPRINT_HEADERS, ...headers }),
        post: (path, body = {}, headers = {}) =>
          agent
            .post(path)
            .set({ ...FINGERPRINT_HEADERS, ...headers })
            .send(body),
        cookie,
        token() {
          const value = cookie(sessionCookieName);
          return value ? decodeURIComponent(value) : undefined;
        },
      };
    },
    getWithToken: (path, token, headers = {}) =>
      request(server)
        .get(path)
        .set({
          ...FINGERPRINT_HEADERS,
          ...headers,
          Cookie: cookieHeader(sessionCookieName, token, headers.Cookie),
        }),
    postWithToken: (path, token, body = {}, headers = {}) =>
      request(server)
        .post(path)
        .set({
          ...FINGERPRINT_HEADERS,
          ...headers,
          Cookie: cookieHeader(sessionCookieName, token, headers.Cookie),
        })
        .send(body),
    async close() {
      if (closed) return;
      closed = true;
      try {
        await app.close();
        for (const stop of dispose) {
          await stop();
        }
      } finally {
        removeDatabase(databasePath);
      }
    },
  };
  return harness;
}

/** Cookie header presenting `token` as the session cookie, plus optional extra cookies. */
function cookieHeader(name: string, token: string, extra?: string): string {
  const pair = `${name}=${encodeURIComponent(token)}`;
  return extra ? `${pair}; ${extra}` : pair;
}

/** Removes a SQLite database together with its WAL and SHM files. */
function removeDatabase(databasePath: string): void {
  for (const suffix of ['', '-shm', '-wal']) {
    rmSync(`${databasePath}${suffix}`, { force: true });
  }
}

/** All `Set-Cookie` entries for `name` in a response. */
export function responseCookies(
  response: HttpResponse,
  name: string,
): Array<{ value: string; deleted: boolean }> {
  const values = response.headers['set-cookie'];
  const setCookies = Array.isArray(values) ? values : values ? [values] : [];
  return setCookies
    .filter((value) => value.startsWith(`${name}=`))
    .map((value: string) => {
      const [pair, ...attributes] = value.split(';');
      const raw = pair.slice(name.length + 1);
      const deleted =
        raw === '' ||
        attributes.some((attribute) => /^\s*max-age=0\s*$/i.test(attribute));
      return { value: decodeURIComponent(raw), deleted };
    });
}

/** Asserts the response delivered a three-segment SCJWT and returns it. */
export function expectScjwt(
  response: HttpResponse,
  sessionCookieName: string,
): string {
  const issued = responseCookies(response, sessionCookieName).filter(
    (cookie) => !cookie.deleted,
  );
  expect(issued).toHaveLength(1);
  const token = issued[0].value;
  expect(token.split('.')).toHaveLength(3);
  return token;
}

/** Asserts the response did not deliver any usable session cookie. */
export function expectNoScjwt(
  response: HttpResponse,
  sessionCookieName: string,
): void {
  const issued = responseCookies(response, sessionCookieName).filter(
    (cookie) => !cookie.deleted,
  );
  expect(issued).toEqual([]);
}

/** Returns the `sid` claim of an SCJWT, failing when it is missing. */
export function sessionIdOf(token: string): string {
  const sid = decodeJwt(token).sid;
  if (typeof sid !== 'string') {
    throw new Error('SCJWT does not contain a session id.');
  }
  return sid;
}
