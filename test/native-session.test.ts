import { describe, expect, test } from "bun:test";
import type { AuthContext, BetterAuthPlugin } from "better-auth";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { parseSetCookieHeader, setSessionCookie } from "better-auth/cookies";
import { testUtils } from "better-auth/plugins";
import { serializeSignedCookie, type EndpointContext } from "better-call";
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
	async function establishSession<Path extends string>(
		ctx: EndpointContext<
			Path,
			{ method: "POST" },
			AuthContext,
			Record<string, string | undefined> | undefined
		>,
	) {
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
			callbackResponseFailureFixture: createAuthEndpoint(
				"/callback-fixture-response-failure",
				{ method: "POST" },
				async (ctx) => {
					await establishSession(ctx);
					return new Response("callback failed", { status: 422 });
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
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
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

		const serializedNativeCookie = await serializeSignedCookie(
			"",
			db.session[0].token,
			context.secret,
		);
		const nativeSessionCookie = decodeURIComponent(
			serializedNativeCookie.replace("=", ""),
		);
		const cookieOnlyResponse = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, nativeSessionCookie),
		);
		expect(await cookieOnlyResponse.json()).toBeNull();
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

	test("issues from callback-style newSession", async () => {
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

		const response = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/callback-fixture`, {
				method: "POST",
				headers: STABLE_HEADERS,
			}),
		);
		const sessionCookie = parseSetCookieHeader(
			response.headers.get("set-cookie") ?? "",
		).get(context.authCookies.sessionToken.name);
		expect(response.status).toBe(200);
		expect(sessionCookie?.value.split(".")).toHaveLength(3);
	});

	test("skips callback issuance for API errors and non-2xx responses", async () => {
		for (const tokenPlacement of ["cookie", "header"] as const) {
			let fixtureUserId = "";
			const fixture = createCallbackFixture(() => fixtureUserId);
			const auth = betterAuth({
				database: memoryAdapter(createMemoryDB()),
				baseURL: TEST_BASE_URL,
				secret: TEST_SECRET,
				session: { cookieCache: { enabled: true } },
				plugins: [testUtils(), fixture, scjwt({ tokenPlacement })],
			});
			const context = await auth.$context;
			const user = await context.test.saveUser(
				context.test.createUser({
					email: `${tokenPlacement}-callback-failure@example.com`,
				}),
			);
			fixtureUserId = user.id;

			for (const [path, status] of [
				["callback-fixture-failure", 400],
				["callback-fixture-response-failure", 422],
			] as const) {
				const response = await auth.handler(
					new Request(`${TEST_BASE_URL}/api/auth/${path}`, {
						method: "POST",
						headers: STABLE_HEADERS,
					}),
				);
				const responseCookies = parseSetCookieHeader(
					response.headers.get("set-cookie") ?? "",
				);
				expect(response.status).toBe(status);
				for (const cookieName of [
					context.authCookies.sessionToken.name,
					context.authCookies.sessionData.name,
					context.authCookies.dontRememberToken.name,
				]) {
					const cookie = responseCookies.get(cookieName);
					expect(cookie?.value).toBe("");
					expect(cookie?.["max-age"]).toBe(0);
				}
				expect(response.headers.get("set-auth-token")).toBeNull();
			}
		}
	});
});
