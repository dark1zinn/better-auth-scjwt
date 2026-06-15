import { expect } from "bun:test";
import type { AuthContext, Session } from "better-auth";
import { betterAuth } from "better-auth";
import { memoryAdapter, type MemoryDB } from "better-auth/adapters/memory";
import type { TestHelpers } from "better-auth/plugins";
import { testUtils } from "better-auth/plugins";
import { DEFAULT_COOKIE_NAME } from "../../src/plugin/constants";
import { computeFingerprint } from "../../src/plugin/fingerprint";
import { signJwtFromParts } from "../../src/plugin/jwt";
import {
	isClearingSetCookie,
	SET_AUTH_TOKEN_HEADER,
} from "../../src/plugin/token-deliver";
import {
	createOnRequest,
	type OnRequestHandler,
} from "../../src/plugin/on-request";
import { getRequestFingerprintInput } from "../../src/plugin/request-context";
import { resolveOptions } from "../../src/plugin/resolve-options";
import type { OnRequestInterrupt } from "../../src/plugin/unauthorized-response";
import type { TokenPlacement } from "../../src/plugin/types";
import { scjwt } from "../../src/plugin/index";
import { getTestContext } from "./auth-test";
import {
	TEST_ISSUER,
	TEST_JWT_SECRET,
} from "./fixtures";

export const TEST_PASSWORD = "password123";

export const STABLE_REQUEST_HEADERS = {
	"user-agent": "Mozilla/5.0 RevokeTest",
} as const;

export const revokeTestOptions = resolveOptions({
	jwtSecret: TEST_JWT_SECRET,
	issuer: TEST_ISSUER,
});

export function createRevokeTestAuth(memoryDB: MemoryDB = {}) {
	return createClearTestAuth(memoryDB);
}

export interface ClearTestAuthOptions {
	tokenPlacement?: TokenPlacement;
	cookieName?: string;
}

export function createClearTestAuth(
	memoryDB: MemoryDB = {},
	options: ClearTestAuthOptions = {},
) {
	return betterAuth({
		database: memoryAdapter(memoryDB),
		secret: "test-auth-secret",
		baseURL: TEST_ISSUER,
		emailAndPassword: { enabled: true },
		plugins: [
			testUtils(),
			scjwt({
				jwtSecret: TEST_JWT_SECRET,
				issuer: TEST_ISSUER,
				tokenPlacement: options.tokenPlacement,
				cookieName: options.cookieName,
			}),
		],
	});
}

export function getSetCookieValues(headers: Headers): string[] {
	if (typeof headers.getSetCookie === "function") {
		return headers.getSetCookie();
	}

	const combined = headers.get("set-cookie");
	if (!combined) {
		return [];
	}

	return combined.split(/,(?=\s*[^;=]+=)/);
}

export function expectScjwtCookieCleared(
	headers: Headers,
	cookieName = DEFAULT_COOKIE_NAME,
): void {
	const setCookies = getSetCookieValues(headers);
	const clearing = setCookies.filter((setCookie) =>
		isClearingSetCookie(setCookie, cookieName),
	);
	expect(clearing.length).toBeGreaterThan(0);
}

export function expectScjwtCookieNotCleared(
	headers: Headers,
	cookieName = DEFAULT_COOKIE_NAME,
): void {
	const setCookies = getSetCookieValues(headers);
	const clearing = setCookies.filter((setCookie) =>
		isClearingSetCookie(setCookie, cookieName),
	);
	expect(clearing).toHaveLength(0);
}

export function expectScjwtHeaderCleared(headers: Headers): void {
	expect(headers.has(SET_AUTH_TOKEN_HEADER)).toBe(false);
}

export async function getScjwtCookieName(
	auth: ReturnType<typeof createClearTestAuth>,
	cookieName = DEFAULT_COOKIE_NAME,
): Promise<string> {
	const ctx = await auth.$context;
	return ctx.createAuthCookie(cookieName, { maxAge: 0 }).name;
}

export async function seedCredentialUser(
	auth: ReturnType<typeof createRevokeTestAuth>,
	test: TestHelpers,
	email = "revoke-test@example.com",
) {
	const ctx = await auth.$context;
	const user = test.createUser({ email });
	const saved = await test.saveUser(user);
	await ctx.internalAdapter.linkAccount({
		userId: saved.id,
		providerId: "credential",
		accountId: saved.id,
		password: await ctx.password.hash(TEST_PASSWORD),
	});
	return saved;
}

export async function mintScjwtToken(
	context: AuthContext,
	session: Session,
	userId: string,
	requestHeaders: HeadersInit = STABLE_REQUEST_HEADERS,
): Promise<string> {
	const headers = new Headers(requestHeaders);
	const { ip, ua, platform } = getRequestFingerprintInput(
		headers,
		context.options,
	);
	const fingerprint = computeFingerprint(ip, ua, platform);

	return signJwtFromParts({
		jwtSecret: TEST_JWT_SECRET,
		issuer: TEST_ISSUER,
		userId,
		fingerprint,
		sessionId: session.id,
		expiresInSeconds: revokeTestOptions.expiresInSeconds,
	});
}

export function createRevokeOnRequestHandler(): OnRequestHandler {
	return createOnRequest(revokeTestOptions);
}

export async function runOnRequestWithToken(
	handler: OnRequestHandler,
	context: AuthContext,
	token: string,
	requestHeaders: HeadersInit = STABLE_REQUEST_HEADERS,
): Promise<OnRequestInterrupt | void> {
	const headers = new Headers(requestHeaders);
	headers.set("cookie", `${DEFAULT_COOKIE_NAME}=${token}`);

	return handler(
		new Request(`${TEST_ISSUER}/api/protected`, { headers }),
		context,
	);
}

export async function expectScjwtRejected(
	result: OnRequestInterrupt | void,
): Promise<void> {
	expect(result?.response.status).toBe(401);

	const body = (await result?.response.json()) as { message?: string };
	expect(body.message).toBe("Session not found.");
}

export async function expectScjwtAccepted(
	result: OnRequestInterrupt | void,
	context: AuthContext,
): Promise<void> {
	expect(result).toBeUndefined();
	expect(context.session).toBeDefined();
}

export async function getRevokeTestContext(
	auth: ReturnType<typeof createRevokeTestAuth>,
): Promise<AuthContext> {
	return getTestContext(auth);
}
