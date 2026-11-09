import { describe, expect, setSystemTime, test } from "bun:test";
import type { BetterAuthOptions } from "better-auth";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { parseSetCookieHeader } from "better-auth/cookies";
import { decodeJwt } from "jose";
import { scjwt } from "../src/plugin/index";
import {
	STABLE_HEADERS,
	TEST_BASE_URL,
	TEST_SECRET,
	createCookieHeaders,
	createMemoryDB,
	requestSession,
	rowAt,
	signUpWithScjwt,
	type TestDB,
} from "./helpers/native-auth";

const PASSWORD = "correct-horse-battery-staple";
const NEW_PASSWORD = "correct-horse-battery-staple-2";

function createAuth(
	db: TestDB,
	session: BetterAuthOptions["session"] = {},
	emailAndPassword: Partial<NonNullable<BetterAuthOptions["emailAndPassword"]>> = {},
) {
	return betterAuth({
		database: memoryAdapter(db),
		baseURL: TEST_BASE_URL,
		secret: TEST_SECRET,
		emailAndPassword: { enabled: true, ...emailAndPassword },
		session,
		plugins: [scjwt()],
	});
}

type Auth = ReturnType<typeof createAuth>;

function issuedCookieToken(response: Response, cookieName: string): string | undefined {
	return parseSetCookieHeader(response.headers.get("set-cookie") ?? "").get(cookieName)?.value;
}

async function at<T>(offsetMs: number, run: () => Promise<T>): Promise<T> {
	setSystemTime(new Date(Date.now() + offsetMs));
	try {
		return await run();
	} finally {
		setSystemTime();
	}
}

async function post(auth: Auth, path: string, headers: Headers, body: object = {}) {
	const request = new Headers(headers);
	request.set("content-type", "application/json");
	return auth.handler(
		new Request(`${TEST_BASE_URL}/api/auth${path}`, {
			method: "POST",
			headers: request,
			body: JSON.stringify(body),
		}),
	);
}

async function signIn(auth: Auth, email: string, password = PASSWORD) {
	const response = await post(auth, "/sign-in/email", new Headers(STABLE_HEADERS), {
		email,
		password,
	});
	expect(response.status).toBe(200);
	const token = issuedCookieToken(response, (await auth.$context).authCookies.sessionToken.name);
	if (!token) throw new Error("sign-in did not issue an SCJWT");
	return token;
}

describe("Better Auth refresh policies", () => {
	test("disableSessionRefresh keeps expiry and issues no replacement", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db, { expiresIn: 3600, updateAge: 0, disableSessionRefresh: true });
		const issued = await signUpWithScjwt(auth, "no-refresh@example.com");
		const before = new Date(rowAt(db.session).expiresAt).getTime();
		const response = await at(2000, () =>
			requestSession(auth, createCookieHeaders(issued.cookieName, issued.token)),
		);
		expect(response.status).toBe(200);
		expect(issuedCookieToken(response, issued.cookieName)).toBeUndefined();
		expect(new Date(rowAt(db.session).expiresAt).getTime()).toBe(before);
	});

	test("the disableRefresh query keeps expiry and issues no replacement", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db, { expiresIn: 3600, updateAge: 0 });
		const issued = await signUpWithScjwt(auth, "query-no-refresh@example.com");
		const before = new Date(rowAt(db.session).expiresAt).getTime();
		const response = await at(2000, () =>
			auth.handler(
				new Request(`${TEST_BASE_URL}/api/auth/get-session?disableRefresh=true`, {
					headers: createCookieHeaders(issued.cookieName, issued.token),
				}),
			),
		);
		expect(response.status).toBe(200);
		expect(issuedCookieToken(response, issued.cookieName)).toBeUndefined();
		expect(new Date(rowAt(db.session).expiresAt).getTime()).toBe(before);
	});

	test("deferred refresh reads on GET and rotates the transport on POST", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db, { expiresIn: 3600, updateAge: 0, deferSessionRefresh: true });
		const issued = await signUpWithScjwt(auth, "deferred@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		const before = new Date(rowAt(db.session).expiresAt).getTime();

		const read = await at(2000, () => requestSession(auth, headers));
		expect(read.status).toBe(200);
		expect(await read.json()).toMatchObject({ needsRefresh: true });
		expect(issuedCookieToken(read, issued.cookieName)).toBeUndefined();
		expect(new Date(rowAt(db.session).expiresAt).getTime()).toBe(before);

		const refreshed = await at(2000, () => post(auth, "/get-session", headers));
		expect(refreshed.status).toBe(200);
		const replacement = issuedCookieToken(refreshed, issued.cookieName);
		expect(decodeJwt(replacement ?? "").sid).toBe(decodeJwt(issued.token).sid);
		expect(new Date(rowAt(db.session).expiresAt).getTime()).toBeGreaterThan(before);
	});

	test("freshAge gates fresh-session routes without ending the session", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db, { freshAge: 60 });
		const issued = await signUpWithScjwt(auth, "fresh@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		const listSessions = () =>
			auth.handler(new Request(`${TEST_BASE_URL}/api/auth/list-sessions`, { headers }));
		expect((await listSessions()).status).toBe(200);
		const stale = await at(2 * 60 * 1000, listSessions);
		expect(stale.status).toBe(403);
		expect(await stale.json()).toMatchObject({ code: "SESSION_NOT_FRESH" });
		expect(db.session).toHaveLength(1);
		expect((await requestSession(auth, headers)).status).toBe(200);
	});
});

describe("password changes and resets", () => {
	test("a default password change keeps every session", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db);
		const email = "keep-sessions@example.com";
		const first = await signUpWithScjwt(auth, email);
		const second = await signIn(auth, email);
		const changed = await post(
			auth,
			"/change-password",
			createCookieHeaders(first.cookieName, first.token),
			{ currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
		);
		expect(changed.status).toBe(200);
		for (const token of [first.token, second]) {
			const response = await requestSession(auth, createCookieHeaders(first.cookieName, token));
			expect(response.status).toBe(200);
		}
	});

	test("revokeOtherSessions replaces the current session and revokes the rest", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db);
		const email = "revoke-others@example.com";
		const first = await signUpWithScjwt(auth, email);
		const second = await signIn(auth, email);
		const changed = await post(
			auth,
			"/change-password",
			createCookieHeaders(first.cookieName, first.token),
			{ currentPassword: PASSWORD, newPassword: NEW_PASSWORD, revokeOtherSessions: true },
		);
		expect(changed.status).toBe(200);
		const replacement = issuedCookieToken(changed, first.cookieName);
		expect(replacement?.split(".")).toHaveLength(3);
		for (const token of [first.token, second]) {
			const response = await requestSession(auth, createCookieHeaders(first.cookieName, token));
			expect(response.status).toBe(401);
		}
		const current = await requestSession(
			auth,
			createCookieHeaders(first.cookieName, replacement ?? ""),
		);
		expect(await current.json()).toMatchObject({ user: { email } });
	});

	test("a password reset keeps sessions unless revocation is configured", async () => {
		let resetToken = "";
		const db = createMemoryDB();
		const auth = createAuth(db, {}, {
			async sendResetPassword({ token }) {
				resetToken = token;
			},
		});
		const email = "reset-keeps@example.com";
		const issued = await signUpWithScjwt(auth, email);
		const json = new Headers({ ...STABLE_HEADERS });
		expect((await post(auth, "/request-password-reset", json, { email })).status).toBe(200);
		expect(
			(await post(auth, "/reset-password", json, { token: resetToken, newPassword: NEW_PASSWORD }))
				.status,
		).toBe(200);
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token),
		);
		expect(response.status).toBe(200);
		await signIn(auth, email, NEW_PASSWORD);
	});
});
