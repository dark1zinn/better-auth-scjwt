import { describe, expect, test } from "bun:test";
import type { BetterAuthPlugin } from "better-auth";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { parseSetCookieHeader, setSessionCookie } from "better-auth/cookies";
import { testUtils } from "better-auth/plugins";
import { decodeJwt } from "jose";
import { scjwt } from "../src/plugin/index";
import {
	STABLE_HEADERS,
	TEST_BASE_URL,
	TEST_SECRET,
	createCookieHeaders,
	createMemoryDB,
	requestSession,
	signUpWithScjwt,
} from "./helpers/native-auth";

function createCallbackFixture(getUserId: () => string): BetterAuthPlugin {
	async function establishSession(ctx: Parameters<Parameters<typeof createAuthEndpoint>[2]>[0]) {
		const user = await ctx.context.internalAdapter.findUserById(getUserId());
		if (!user) throw APIError.fromStatus("NOT_FOUND");
		const session = await ctx.context.internalAdapter.createSession(user.id);
		await setSessionCookie(ctx, { session, user });
	}
	return {
		id: "scjwt-callback-fixture",
		endpoints: {
			callbackFixture: createAuthEndpoint(
				"/callback-fixture",
				{ method: "POST" },
				async (ctx) => {
					await establishSession(ctx);
					return ctx.json({ ok: true });
				},
			),
			callbackFailureFixture: createAuthEndpoint(
				"/callback-fixture-failure",
				{ method: "POST" },
				async (ctx) => {
					await establishSession(ctx);
					throw APIError.fromStatus("BAD_REQUEST");
				},
			),
		},
	};
}

describe("native Better Auth session transport", () => {
	test("uses the resolved native cookie and normal get-session flow", async () => {
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			session: { expiresIn: 1800, cookieCache: { enabled: true } },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "native-cookie@example.com");
		expect(issued.cookieName).toBe("better-auth.session_token");
		expect(issued.token.split(".")).toHaveLength(3);

		const cookies = parseSetCookieHeader(
			issued.response.headers.get("set-cookie") ?? "",
		);
		const context = await auth.$context;
		expect(cookies.get(context.authCookies.sessionData.name)?.value).toBeTruthy();

		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token),
		);
		expect(response.status).toBe(200);
		const body = (await response.json()) as { user: { email: string } };
		expect(body.user.email).toBe("native-cookie@example.com");

		const payload = decodeJwt(issued.token);
		const backingSession = db.session[0];
		expect(payload.exp).toBeLessThanOrEqual(
			Math.floor(new Date(backingSession.expiresAt).getTime() / 1000),
		);
		expect(payload.exp).toBeLessThanOrEqual((payload.iat ?? 0) + 1800);
	});

	test("honors secure custom cookie prefixes for delivery and extraction", async () => {
		const baseURL = "https://auth.example.com";
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			advanced: { cookiePrefix: "tenant-auth", useSecureCookies: true },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(
			auth,
			"secure-prefix@example.com",
			STABLE_HEADERS,
			baseURL,
		);
		expect(issued.cookieName).toBe("__Secure-tenant-auth.session_token");
		const cookie = parseSetCookieHeader(
			issued.response.headers.get("set-cookie") ?? "",
		).get(issued.cookieName);
		expect(cookie?.secure).toBe(true);
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token),
			baseURL,
		);
		expect(await response.json()).toMatchObject({
			user: { email: "secure-prefix@example.com" },
		});
	});

	test("uses header placement exclusively and exposes the replacement header once", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			session: { cookieCache: { enabled: true } },
			plugins: [scjwt({ tokenPlacement: "header" })],
		});
		const issued = await signUpWithScjwt(auth, "header@example.com");
		expect(issued.response.headers.get("set-auth-token")).toBe(issued.token);
		const exposed = (
			issued.response.headers.get("access-control-expose-headers") ?? ""
		)
			.split(",")
			.map((value) => value.trim().toLowerCase());
		expect(exposed.filter((value) => value === "set-auth-token")).toHaveLength(1);
		const context = await auth.$context;
		const cookies = parseSetCookieHeader(
			issued.response.headers.get("set-cookie") ?? "",
		);
		expect(cookies.get(context.authCookies.sessionToken.name)?.value).toBeFalsy();
		expect(cookies.get(context.authCookies.sessionData.name)?.value).toBeFalsy();

		const headers = new Headers(STABLE_HEADERS);
		headers.set("authorization", `Bearer ${issued.token}`);
		headers.set("cookie", `${issued.cookieName}=ignored.invalid.cookie`);
		const response = await requestSession(auth, headers);
		expect(await response.json()).toMatchObject({ user: { email: "header@example.com" } });
	});

	test("cookie placement ignores an Authorization token", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "cookie-precedence@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		headers.set("authorization", "Bearer invalid.invalid.invalid");
		const response = await requestSession(auth, headers);
		expect(await response.json()).toMatchObject({
			user: { email: "cookie-precedence@example.com" },
		});
	});

	test("rejects an SCJWT immediately after the core sign-out deletes its session", async () => {
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "sign-out@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		await auth.api.signOut({ headers });
		expect(db.session).toHaveLength(0);
		const response = await requestSession(auth, headers);
		expect(response.status).toBe(401);
	});

	test("issues from callback-style newSession and skips failed responses", async () => {
		let fixtureUserId = "";
		const fixture = createCallbackFixture(() => fixtureUserId);
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			plugins: [testUtils(), fixture, scjwt()],
		});
		const context = await auth.$context;
		const user = await context.test.saveUser(
			context.test.createUser({ email: "callback@example.com" }),
		);
		fixtureUserId = user.id;

		const success = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/callback-fixture`, {
				method: "POST",
				headers: STABLE_HEADERS,
			}),
		);
		const successCookie = parseSetCookieHeader(
			success.headers.get("set-cookie") ?? "",
		).get(context.authCookies.sessionToken.name);
		expect(success.status).toBe(200);
		expect(successCookie?.value.split(".")).toHaveLength(3);

		const failure = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/callback-fixture-failure`, {
				method: "POST",
				headers: STABLE_HEADERS,
			}),
		);
		const failureCookie = parseSetCookieHeader(
			failure.headers.get("set-cookie") ?? "",
		).get(context.authCookies.sessionToken.name);
		expect(failure.status).toBe(400);
		expect(failureCookie?.value.split(".").length).not.toBe(3);
	});
});
