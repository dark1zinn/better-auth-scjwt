import type { AuthContext, Session } from "better-auth";
import type { MemoryDB } from "better-auth/adapters/memory";
import { parseSetCookieHeader } from "better-auth/cookies";
import { computeFingerprint } from "../../src/plugin/fingerprint";
import { signJwtFromParts } from "../../src/plugin/jwt";
import { getRequestFingerprintInput } from "../../src/plugin/request-context";
import type { FingerprintMode } from "../../src/plugin/types";

export const TEST_BASE_URL = "http://localhost:3000";
export const TEST_SECRET = "better-auth-scjwt-test-secret-at-least-32-bytes";
export const STABLE_HEADERS = {
	"user-agent": "better-auth-scjwt-test",
	"sec-ch-ua-platform": '"Linux"',
} as const;

export interface TestAuth {
	handler(request: Request): Promise<Response>;
	$context: Promise<AuthContext>;
}

export interface IssuedToken {
	response: Response;
	cookieName: string;
	token: string;
}

export function createMemoryDB(): MemoryDB {
	return { user: [], session: [], account: [], verification: [] };
}

export async function signUpWithScjwt(
	auth: TestAuth,
	email: string,
	headers: HeadersInit = STABLE_HEADERS,
	baseURL = TEST_BASE_URL,
): Promise<IssuedToken> {
	const response = await auth.handler(
		new Request(`${baseURL}/api/auth/sign-up/email`, {
			method: "POST",
			headers: { "content-type": "application/json", ...Object.fromEntries(new Headers(headers)) },
			body: JSON.stringify({
				name: "SCJWT Test User",
				email,
				password: "correct-horse-battery-staple",
			}),
		}),
	);
	if (!response.ok) {
		throw new Error(`sign-up failed: ${response.status} ${await response.text()}`);
	}
	const context = await auth.$context;
	const cookieName = context.authCookies.sessionToken.name;
	const sessionCookie = parseSetCookieHeader(
		response.headers.get("set-cookie") ?? "",
	).get(cookieName);
	const token = response.headers.get("set-auth-token") ?? sessionCookie?.value;
	if (!token) {
		throw new Error("SCJWT was not delivered by the sign-up response.");
	}
	return { response, cookieName, token };
}

export function createCookieHeaders(
	cookieName: string,
	token: string,
	extra: HeadersInit = STABLE_HEADERS,
): Headers {
	const headers = new Headers(extra);
	headers.set("cookie", `${cookieName}=${encodeURIComponent(token)}`);
	return headers;
}

export async function requestSession(
	auth: TestAuth,
	headers: HeadersInit,
	baseURL = TEST_BASE_URL,
): Promise<Response> {
	return auth.handler(
		new Request(`${baseURL}/api/auth/get-session`, { headers }),
	);
}

export async function mintScjwt(
	context: AuthContext,
	session: Session,
	headers: HeadersInit = STABLE_HEADERS,
	fingerprintMode: FingerprintMode = "strict",
): Promise<string> {
	const requestHeaders = new Headers(headers);
	const input = getRequestFingerprintInput(
		requestHeaders,
		context.options,
		fingerprintMode,
	);
	const issuedAt = Math.floor(Date.now() / 1000);
	return signJwtFromParts({
		secretConfig: context.secretConfig,
		issuer: context.baseURL,
		userId: session.userId,
		fingerprint: await computeFingerprint(input.ip, input.ua, input.platform),
		sessionId: session.id,
		expiresAt: Math.min(
			Math.floor(new Date(session.expiresAt).getTime() / 1000),
			issuedAt + context.sessionConfig.expiresIn,
		),
		issuedAt,
	});
}
