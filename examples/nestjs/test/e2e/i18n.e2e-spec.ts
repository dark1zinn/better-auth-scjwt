import { i18n } from '@better-auth/i18n';
import {
  createNestAuthHarness,
  expectNoScjwt,
  expectScjwt,
  PASSWORD,
  type AuthClient,
} from './support/nest-auth-harness.js';
import {
  ENGLISH_TRANSLATIONS,
  FRENCH_TRANSLATIONS,
  i18nOptions,
  localeUserField,
} from './support/plugin-fixtures.js';

describe('NestJS i18n profile', () => {
  let harness: Awaited<
    ReturnType<typeof createNestAuthHarness<[ReturnType<typeof i18n>]>>
  >;
  let cookieName: string;

  beforeAll(async () => {
    harness = await createNestAuthHarness({
      name: 'i18n',
      additionalPlugins: [i18n(i18nOptions)],
      user: localeUserField,
    });
    cookieName = harness.sessionCookieName;
  });

  afterAll(async () => {
    await harness?.close();
  });

  /** Signs up (optionally storing a preferred locale) and asserts an SCJWT was issued. */
  async function signUp(client: AuthClient, email: string, locale?: string) {
    const response = await client.post('/api/auth/sign-up/email', {
      name: 'Locale User',
      email,
      password: PASSWORD,
      ...(locale ? { locale } : {}),
    });
    expect(response.status).toBe(200);
    expectScjwt(response, cookieName);
    return response;
  }

  it('translates errors by header, falls back for unsupported locales, and honors cookie precedence', async () => {
    const email = 'i18n-header@example.com';
    await signUp(harness.createClient(), email);

    const english = await harness
      .createClient()
      .post(
        '/api/auth/sign-in/email',
        { email, password: 'wrong-password' },
        { 'Accept-Language': 'en' },
      );
    expect(english.status).toBe(401);
    expect(english.body.code).toBe('INVALID_EMAIL_OR_PASSWORD');
    expect(english.body.message).toBe(
      ENGLISH_TRANSLATIONS.INVALID_EMAIL_OR_PASSWORD,
    );
    expectNoScjwt(english, cookieName);

    const french = await harness
      .createClient()
      .post(
        '/api/auth/sign-in/email',
        { email, password: 'wrong-password' },
        { 'Accept-Language': 'fr-CA, fr;q=0.9, en;q=0.8' },
      );
    expect(french.status).toBe(401);
    expect(french.body.code).toBe('INVALID_EMAIL_OR_PASSWORD');
    expect(french.body.message).toBe(
      FRENCH_TRANSLATIONS.INVALID_EMAIL_OR_PASSWORD,
    );
    expect(french.body.originalMessage).toBe(english.body.message);
    expectNoScjwt(french, cookieName);

    const unsupported = await harness
      .createClient()
      .post(
        '/api/auth/sign-in/email',
        { email, password: 'wrong-password' },
        { 'Accept-Language': 'de' },
      );
    expect(unsupported.status).toBe(401);
    expect(unsupported.body.code).toBe('INVALID_EMAIL_OR_PASSWORD');
    expect(unsupported.body.message).toBe(
      ENGLISH_TRANSLATIONS.INVALID_EMAIL_OR_PASSWORD,
    );
    expectNoScjwt(unsupported, cookieName);

    const cookieWins = await harness
      .createClient()
      .post(
        '/api/auth/sign-in/email',
        { email, password: 'wrong-password' },
        { Cookie: 'locale=fr', 'Accept-Language': 'en' },
      );
    expect(cookieWins.status).toBe(401);
    expect(cookieWins.body.code).toBe('INVALID_EMAIL_OR_PASSWORD');
    expect(cookieWins.body.message).toBe(
      FRENCH_TRANSLATIONS.INVALID_EMAIL_OR_PASSWORD,
    );
    expectNoScjwt(cookieWins, cookieName);
  });

  it('uses the SCJWT-resolved user locale for authenticated errors and preserves successful sessions', async () => {
    const frenchClient = harness.createClient();
    const frenchEmail = 'i18n-french-user@example.com';
    await signUp(frenchClient, frenchEmail, 'fr');

    const session = await frenchClient.get('/api/auth/get-session');
    expect(session.status).toBe(200);
    expect(session.body.user.locale).toBe('fr');
    const me = await frenchClient.get('/me');
    expect(me.status).toBe(200);
    expect(me.body).toEqual({ id: session.body.user.id, email: frenchEmail });

    const frenchChange = await frenchClient.post('/api/auth/change-password', {
      currentPassword: 'wrong-password',
      newPassword: 'another-password',
    });
    expect(frenchChange.status).toBe(400);
    expect(frenchChange.body.code).toBe('INVALID_PASSWORD');
    expect(frenchChange.body.message).toBe(
      FRENCH_TRANSLATIONS.INVALID_PASSWORD,
    );
    expectNoScjwt(frenchChange, cookieName);

    const englishClient = harness.createClient();
    const englishEmail = 'i18n-english-user@example.com';
    await signUp(englishClient, englishEmail, 'en');
    const englishChange = await englishClient.post(
      '/api/auth/change-password',
      {
        currentPassword: 'wrong-password',
        newPassword: 'another-password',
      },
    );
    expect(englishChange.status).toBe(400);
    expect(englishChange.body.code).toBe('INVALID_PASSWORD');
    expect(englishChange.body.message).toBe(
      ENGLISH_TRANSLATIONS.INVALID_PASSWORD,
    );
    expectNoScjwt(englishChange, cookieName);
  });
});
