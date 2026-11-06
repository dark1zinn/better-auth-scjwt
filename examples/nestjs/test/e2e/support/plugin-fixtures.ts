import type { TranslationDictionary } from '@better-auth/i18n';
import { createAccessControl } from 'better-auth/plugins/access';
import { defaultStatements } from 'better-auth/plugins/admin/access';
import type { EmailOTPOptions } from 'better-auth/plugins/email-otp';

// ---------------------------------------------------------------------------
// Admin RBAC
// ---------------------------------------------------------------------------

export const rbacStatements = {
  ...defaultStatements,
  project: ['read', 'create', 'delete'],
} as const;

export const rbacAccessControl = createAccessControl(rbacStatements);

export const rbacRoles = {
  admin: rbacAccessControl.newRole({
    user: [...defaultStatements.user],
    session: [...defaultStatements.session],
    project: ['read', 'create', 'delete'],
  }),
  auditor: rbacAccessControl.newRole({
    user: [],
    session: [],
    project: ['read'],
  }),
  user: rbacAccessControl.newRole({
    user: [],
    session: [],
    project: [],
  }),
};

/** Options for `admin()` using the custom project statement and roles. */
export const rbacAdminOptions = {
  ac: rbacAccessControl,
  roles: rbacRoles,
  adminRoles: ['admin'],
};

// ---------------------------------------------------------------------------
// i18n
// ---------------------------------------------------------------------------

export const ENGLISH_TRANSLATIONS = {
  INVALID_EMAIL_OR_PASSWORD: 'Invalid email or password',
  INVALID_PASSWORD: 'Invalid password',
} satisfies TranslationDictionary;

export const FRENCH_TRANSLATIONS = {
  INVALID_EMAIL_OR_PASSWORD: 'E-mail ou mot de passe invalide',
  INVALID_PASSWORD: 'Mot de passe invalide',
  INVALID_USERNAME_OR_PASSWORD: "Nom d'utilisateur ou mot de passe invalide",
  INVALID_OTP: 'Code OTP invalide',
  YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE:
    "Vous n'êtes pas autorisé à modifier le rôle des utilisateurs",
} satisfies TranslationDictionary;

/** Deterministic i18n options: cookie wins over header, then the stored user locale. */
export const i18nOptions = {
  translations: { en: ENGLISH_TRANSLATIONS, fr: FRENCH_TRANSLATIONS },
  defaultLocale: 'en' as const,
  detection: ['cookie' as const, 'header' as const, 'session' as const],
  localeCookie: 'locale',
};

/** Optional user field read by i18n's `session` detection strategy. */
export const localeUserField = {
  additionalFields: {
    locale: { type: 'string' as const, required: false },
  },
};

// ---------------------------------------------------------------------------
// Captcha
// ---------------------------------------------------------------------------

export const CAPTCHA_PASS = 'captcha-pass';
export const CAPTCHA_REJECT = 'captcha-reject';
export const CAPTCHA_ERROR = 'captcha-error';
export const CAPTCHA_SECRET = 'test-secret';

export interface CaptchaVerifier {
  url: string;
  /** Every siteverify request body received, in order. */
  requests: Array<{ secret?: string; response?: string; remoteip?: string }>;
  stop: () => Promise<void>;
}

/**
 * Ephemeral Cloudflare Turnstile siteverify stand-in for
 * `captcha({ siteVerifyURLOverride })`; no external service is contacted.
 */
export function startCaptchaVerifier(): CaptchaVerifier {
  const requests: CaptchaVerifier['requests'] = [];
  const server = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    async fetch(request) {
      const body =
        (await request.json()) as CaptchaVerifier['requests'][number];
      requests.push(body);
      if (body.secret !== CAPTCHA_SECRET) {
        return Response.json({
          success: false,
          'error-codes': ['invalid-input-secret'],
        });
      }
      switch (body.response) {
        case CAPTCHA_PASS:
          return Response.json({ success: true });
        case CAPTCHA_ERROR:
          return new Response('verifier unavailable', { status: 500 });
        default:
          return Response.json({
            success: false,
            'error-codes': ['invalid-input-response'],
          });
      }
    },
  });
  return {
    url: `http://127.0.0.1:${server.port}/siteverify`,
    requests,
    stop: () => server.stop(true),
  };
}

export function captchaHeaders(response: string): Record<string, string> {
  return { 'x-captcha-response': response };
}

// ---------------------------------------------------------------------------
// Email OTP
// ---------------------------------------------------------------------------

export type OtpType = Parameters<
  EmailOTPOptions['sendVerificationOTP']
>[0]['type'];

export interface OtpDelivery {
  email: string;
  otp: string;
  type: OtpType;
}

export interface OtpCapture {
  /** Options to spread into `emailOTP({ ... })`. */
  options: Pick<EmailOTPOptions, 'generateOTP' | 'sendVerificationOTP'>;
  deliveries: OtpDelivery[];
  /** Latest code delivered to `email` for `type`; throws when none was sent. */
  latest(email: string, type: OtpType): string;
  count(email: string, type: OtpType): number;
}

/** Deterministic OTP generator (100001, 100002, …) with in-memory delivery. */
export function createOtpCapture(): OtpCapture {
  const deliveries: OtpDelivery[] = [];
  let sequence = 100_000;
  const forAddress = (email: string, type: OtpType) =>
    deliveries.filter(
      (delivery) =>
        delivery.email === email.toLowerCase() && delivery.type === type,
    );
  return {
    deliveries,
    options: {
      generateOTP: () => String(++sequence),
      async sendVerificationOTP({ email, otp, type }) {
        deliveries.push({ email: email.toLowerCase(), otp, type });
      },
    },
    latest(email, type) {
      const delivery = forAddress(email, type).at(-1);
      if (!delivery) {
        throw new Error(`No ${type} OTP was delivered to ${email}.`);
      }
      return delivery.otp;
    },
    count: (email, type) => forAddress(email, type).length,
  };
}
