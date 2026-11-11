import { describe, expect, setSystemTime, test } from "bun:test";
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
	rowAt,
	signUpWithScjwt,
} from "./helpers/native-auth";

const RAW_REDIRECT_STATUSES = [302, 303, 307] as const;

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
			callbackRedirectFixture: createAuthEndpoint(
				"/callback-fixture-redirect",
				{ method: "POST" },
				async (ctx) => {
					await establishSession(ctx);
					throw ctx.redirect("/signed-in");
				},
			),
			unrelatedFailureFixture: createAuthEndpoint(
				"/unrelated-failure",
				{ method: "POST" },
				async () => {
					throw APIError.fromStatus("BAD_REQUEST");
				},
			),
			unrelatedResponseFailureFixture: createAuthEndpoint(
				"/unrelated-response-failure",
				{ method: "POST" },
				async () => new Response("request failed", { status: 422 }),
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
			callbackServerFailureFixture: createAuthEndpoint(
				"/callback-fixture-server-failure",
				{ method: "POST" },
				async (ctx) => {
					await establishSession(ctx);
					return new Response("callback crashed", { status: 500 });
				},
			),
			...Object.fromEntries(
				RAW_REDIRECT_STATUSES.map((status) => [
					`callbackRawRedirect${status}Fixture`,
					createAuthEndpoint(
						`/callback-fixture-raw-redirect-${status}`,
						{ method: "POST" },
						async (ctx) => {
							await establishSession(ctx);
							return new Response(null, {
								status,
								headers: { location: "/signed-in" },
							});
						},
					),
				]),
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
		const backingSession = rowAt(db.session);
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
			rowAt(db.session).token,
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

	test("issues usable SCJWTs on successful callback redirects", async () => {
		for (const tokenPlacement of ["cookie", "header"] as const) {
			let fixtureUserId = "";
			const auth = betterAuth({
				database: memoryAdapter(createMemoryDB()),
				baseURL: TEST_BASE_URL,
				secret: TEST_SECRET,
				session: { cookieCache: { enabled: true } },
				plugins: [testUtils(), createCallbackFixture(() => fixtureUserId), scjwt({ tokenPlacement })],
			});
			const context = await auth.$context;
			const user = await context.test.saveUser(context.test.createUser());
			fixtureUserId = user.id;
			const response = await auth.handler(
				new Request(`${TEST_BASE_URL}/api/auth/callback-fixture-redirect`, {
					method: "POST",
					headers: STABLE_HEADERS,
				}),
			);
			expect(response.status).toBe(302);
			expect(response.headers.get("location")).toBe("/signed-in");
			const cookies = parseSetCookieHeader(response.headers.get("set-cookie") ?? "");
			const token = tokenPlacement === "cookie"
				? cookies.get(context.authCookies.sessionToken.name)?.value
				: response.headers.get("set-auth-token");
			expect(token?.split(".")).toHaveLength(3);
			if (tokenPlacement === "cookie") {
				expect(cookies.get(context.authCookies.sessionData.name)?.value).toBeTruthy();
			} else {
				expect(cookies.has(context.authCookies.sessionToken.name)).toBe(false);
				expect(cookies.has(context.authCookies.sessionData.name)).toBe(false);
			}
			const headers = tokenPlacement === "cookie"
				? createCookieHeaders(context.authCookies.sessionToken.name, token!)
				: new Headers({ ...STABLE_HEADERS, authorization: `Bearer ${token}` });
			const sessionResponse = await requestSession(auth, headers);
			expect(sessionResponse.status).toBe(200);
			expect(await sessionResponse.json()).toMatchObject({ user: { id: user.id } });
		}
	});

	test("issues usable SCJWTs on raw redirect responses and keeps the redirect", async () => {
		for (const tokenPlacement of ["cookie", "header"] as const) {
			for (const status of RAW_REDIRECT_STATUSES) {
				let fixtureUserId = "";
				const auth = betterAuth({
					database: memoryAdapter(createMemoryDB()),
					baseURL: TEST_BASE_URL,
					secret: TEST_SECRET,
					plugins: [
						testUtils(),
						createCallbackFixture(() => fixtureUserId),
						scjwt({ tokenPlacement }),
					],
				});
				const context = await auth.$context;
				const user = await context.test.saveUser(context.test.createUser());
				fixtureUserId = user.id;
				const response = await auth.handler(
					new Request(
						`${TEST_BASE_URL}/api/auth/callback-fixture-raw-redirect-${status}`,
						{ method: "POST", headers: STABLE_HEADERS },
					),
				);
				expect(response.status).toBe(status);
				expect(response.headers.get("location")).toBe("/signed-in");
				const sessionCookie = parseSetCookieHeader(
					response.headers.get("set-cookie") ?? "",
				).get(context.authCookies.sessionToken.name);
				const token = tokenPlacement === "cookie"
					? sessionCookie?.value
					: response.headers.get("set-auth-token");
				expect(token?.split(".")).toHaveLength(3);
				if (tokenPlacement === "header") {
					expect(sessionCookie).toBeUndefined();
				}
				const headers = tokenPlacement === "cookie"
					? createCookieHeaders(context.authCookies.sessionToken.name, token ?? "")
					: new Headers({ ...STABLE_HEADERS, authorization: `Bearer ${token}` });
				const sessionResponse = await requestSession(auth, headers);
				expect(sessionResponse.status).toBe(200);
				expect(await sessionResponse.json()).toMatchObject({ user: { id: user.id } });
			}
		}
	});

	test("preserves an existing session on unrelated failed requests", async () => {
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			session: { cookieCache: { enabled: true } },
			plugins: [createCallbackFixture(() => ""), scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "unrelated-failure@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		for (const [path, status] of [
			["unrelated-failure", 400],
			["unrelated-response-failure", 422],
		] as const) {
			const response = await auth.handler(
				new Request(`${TEST_BASE_URL}/api/auth/${path}`, { method: "POST", headers }),
			);
			expect(response.status).toBe(status);
			expect(response.headers.get("set-cookie")).toBeNull();
			expect(response.headers.get("set-auth-token")).toBeNull();
			expect(db.session).toHaveLength(1);
			const sessionResponse = await requestSession(auth, headers);
			expect(await sessionResponse.json()).toMatchObject({
				user: { email: "unrelated-failure@example.com" },
			});
		}
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
				["callback-fixture-server-failure", 500],
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

	test("re-issues the same session ID when get-session refreshes the native session", async () => {
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			session: { expiresIn: 3600, updateAge: 0 },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "refresh@example.com");
		const sessionId = decodeJwt(issued.token).sid;
		const expiresBefore = new Date(rowAt(db.session).expiresAt).getTime();
		// Advance the mocked clock so the refresh changes iat/expiresAt without sleeping.
		setSystemTime(new Date(Date.now() + 2000));
		let refreshed: Response;
		try {
			refreshed = await requestSession(
				auth,
				createCookieHeaders(issued.cookieName, issued.token),
			);
		} finally {
			setSystemTime();
		}
		expect(refreshed.status).toBe(200);
		const replacement = readIssuedCookieToken(refreshed, issued.cookieName);
		expect(replacement.split(".")).toHaveLength(3);
		expect(replacement).not.toBe(issued.token);
		expect(decodeJwt(replacement).sid).toBe(sessionId);
		expect(new Date(rowAt(db.session).expiresAt).getTime()).toBeGreaterThan(
			expiresBefore,
		);

		const replacementHeaders = createCookieHeaders(issued.cookieName, replacement);
		const signOut = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/sign-out`, {
				method: "POST",
				headers: withOrigin(replacementHeaders),
			}),
		);
		expect(signOut.status).toBe(200);
		for (const token of [issued.token, replacement]) {
			const response = await requestSession(
				auth,
				createCookieHeaders(issued.cookieName, token),
			);
			expect(response.status).toBe(401);
		}
	});

	test("re-issues the same session ID from update-session with native additional fields", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			session: {
				additionalFields: {
					deviceLabel: { type: "string", required: false },
				},
			},
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "update-session@example.com");
		const sessionId = decodeJwt(issued.token).sid;

		const updated = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/update-session`, {
				method: "POST",
				headers: withOrigin(
					createCookieHeaders(issued.cookieName, issued.token, {
						...STABLE_HEADERS,
						"content-type": "application/json",
					}),
				),
				body: JSON.stringify({ deviceLabel: "work laptop" }),
			}),
		);
		expect(updated.status).toBe(200);
		const updatedBody = (await updated.json()) as {
			session: { id: string; deviceLabel?: string };
		};
		expect(updatedBody.session).toMatchObject({
			id: sessionId,
			deviceLabel: "work laptop",
		});
		const replacement = readIssuedCookieToken(updated, issued.cookieName);
		expect(decodeJwt(replacement).sid).toBe(sessionId);

		const replacementHeaders = createCookieHeaders(issued.cookieName, replacement);
		const current = await requestSession(auth, replacementHeaders);
		expect(current.status).toBe(200);
		expect(await current.json()).toMatchObject({
			session: { id: sessionId, deviceLabel: "work laptop" },
			user: { email: "update-session@example.com" },
		});

		const revoke = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/revoke-sessions`, {
				method: "POST",
				headers: withOrigin(replacementHeaders),
			}),
		);
		expect(revoke.status).toBe(200);
		for (const token of [issued.token, replacement]) {
			const response = await requestSession(
				auth,
				createCookieHeaders(issued.cookieName, token),
			);
			expect(response.status).toBe(401);
		}
	});
});

describe("core Better Auth revocation paths", () => {
	const PASSWORD = "correct-horse-battery-staple";

	/** Signs in through the core email endpoint and returns the raw response. */
	async function signIn(
		auth: { handler(request: Request): Promise<Response> },
		email: string,
		password = PASSWORD,
	) {
		return auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/sign-in/email`, {
				method: "POST",
				headers: { ...STABLE_HEADERS, "content-type": "application/json" },
				body: JSON.stringify({ email, password }),
			}),
		);
	}

	test("rejects every SCJWT after the user deletes their account", async () => {
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			user: { deleteUser: { enabled: true } },
			plugins: [scjwt()],
		});
		const email = "delete-user@example.com";
		const first = await signUpWithScjwt(auth, email);
		const second = readIssuedCookieToken(await signIn(auth, email), first.cookieName);

		const deleted = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/delete-user`, {
				method: "POST",
				headers: withOrigin(
					createCookieHeaders(first.cookieName, second, {
						...STABLE_HEADERS,
						"content-type": "application/json",
					}),
				),
				body: JSON.stringify({ password: PASSWORD }),
			}),
		);
		expect(deleted.status).toBe(200);
		expect(db.user).toHaveLength(0);
		for (const token of [first.token, second]) {
			const response = await requestSession(
				auth,
				createCookieHeaders(first.cookieName, token),
			);
			expect(response.status).toBe(401);
		}
	});

	test("rejects pre-reset SCJWTs when password reset revokes sessions", async () => {
		let resetToken = "";
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: {
				enabled: true,
				revokeSessionsOnPasswordReset: true,
				async sendResetPassword({ token }) {
					resetToken = token;
				},
			},
			plugins: [scjwt()],
		});
		const email = "core-reset@example.com";
		const issued = await signUpWithScjwt(auth, email);
		const jsonHeaders = { ...STABLE_HEADERS, "content-type": "application/json" };

		const requested = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/request-password-reset`, {
				method: "POST",
				headers: jsonHeaders,
				body: JSON.stringify({ email }),
			}),
		);
		expect(requested.status).toBe(200);
		expect(resetToken).not.toBe("");

		const reset = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/reset-password`, {
				method: "POST",
				headers: jsonHeaders,
				body: JSON.stringify({
					token: resetToken,
					newPassword: `${PASSWORD}-reset`,
				}),
			}),
		);
		expect(reset.status).toBe(200);
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token),
		);
		expect(response.status).toBe(401);
		expect((await signIn(auth, email)).status).toBe(401);
		expect((await signIn(auth, email, `${PASSWORD}-reset`)).status).toBe(200);
	});
});

describe("HTTP transport boundaries", () => {
	function createAuth(tokenPlacement: "cookie" | "header", db = createMemoryDB()) {
		return betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			// Better Auth skips origin checks when NODE_ENV is "test"; restore production behavior.
			advanced: { disableOriginCheck: false },
			session: {
				additionalFields: { deviceLabel: { type: "string", required: false } },
			},
			plugins: [scjwt({ tokenPlacement })],
		});
	}

	function updateSession(
		auth: ReturnType<typeof createAuth>,
		headers: Headers,
		origin: string | null,
	) {
		const request = new Headers(headers);
		request.set("content-type", "application/json");
		if (origin) request.set("origin", origin);
		return auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/update-session`, {
				method: "POST",
				headers: request,
				body: JSON.stringify({ deviceLabel: "changed" }),
			}),
		);
	}

	test("cookie placement keeps Better Auth's origin check for state-changing requests", async () => {
		const auth = createAuth("cookie");
		const issued = await signUpWithScjwt(auth, "origin-cookie@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		for (const origin of ["https://evil.example.com", null]) {
			const rejected = await updateSession(auth, headers, origin);
			expect(rejected.status).toBe(403);
			expect(rejected.headers.get("set-cookie")).toBeNull();
		}
		const session = (await (await requestSession(auth, headers)).json()) as {
			session: { deviceLabel?: string | null };
		};
		expect(session.session.deviceLabel ?? null).toBeNull();
		const accepted = await updateSession(auth, headers, TEST_BASE_URL);
		expect(accepted.status).toBe(200);
		expect(readIssuedCookieToken(accepted, issued.cookieName).split(".")).toHaveLength(3);
	});

	test("header placement is not ambient, so Better Auth does not origin-check Bearer requests", async () => {
		const auth = createAuth("header");
		const issued = await signUpWithScjwt(auth, "origin-header@example.com");
		const headers = new Headers({ ...STABLE_HEADERS, authorization: `Bearer ${issued.token}` });
		const response = await updateSession(auth, headers, "https://evil.example.com");
		expect(response.status).toBe(200);
		expect(response.headers.get("set-auth-token")?.split(".")).toHaveLength(3);
	});

	test("a present but invalid credential never falls back to the other transport", async () => {
		const db = createMemoryDB();
		const auth = createAuth("header", db);
		const issued = await signUpWithScjwt(auth, "no-fallback-header@example.com");
		const context = await auth.$context;
		// A validly signed native session cookie for the live session.
		const nativeCookie = decodeURIComponent(
			(await serializeSignedCookie("", rowAt(db.session).token, context.secret)).replace(
				"=",
				"",
			),
		);
		const nativeOnly = createCookieHeaders(issued.cookieName, nativeCookie);
		// Header placement ignores the native cookie entirely when no Bearer is present.
		expect(await (await requestSession(auth, nativeOnly)).json()).toBeNull();
		const headers = createCookieHeaders(issued.cookieName, nativeCookie);
		headers.set("authorization", "Bearer not.a.jwt");
		expect((await requestSession(auth, headers)).status).toBe(401);

		const cookieAuth = createAuth("cookie");
		const cookieIssued = await signUpWithScjwt(cookieAuth, "no-fallback-cookie@example.com");
		const cookieHeaders = createCookieHeaders(cookieIssued.cookieName, "not.a.jwt");
		cookieHeaders.set("authorization", `Bearer ${cookieIssued.token}`);
		expect((await requestSession(cookieAuth, cookieHeaders)).status).toBe(401);
	});

	test("parses only the Bearer scheme and treats empty credentials as missing", async () => {
		const auth = createAuth("header");
		const issued = await signUpWithScjwt(auth, "bearer-parsing@example.com");
		const withAuthorization = (value: string) =>
			requestSession(auth, new Headers({ ...STABLE_HEADERS, authorization: value }));
		const lowercase = await withAuthorization(`bearer ${issued.token}`);
		expect(await lowercase.json()).toMatchObject({
			user: { email: "bearer-parsing@example.com" },
		});
		for (const missing of ["Bearer", "Bearer    ", `Basic ${issued.token}`, issued.token]) {
			const response = await withAuthorization(missing);
			expect(response.status).toBe(200);
			expect(await response.json()).toBeNull();
		}
		expect((await withAuthorization("Bearer a.b")).status).toBe(401);
	});
});

function withOrigin(headers: Headers): Headers {
	const result = new Headers(headers);
	result.set("origin", TEST_BASE_URL);
	return result;
}

/** Returns the SCJWT a response set in `cookieName`, failing when none was delivered. */
function readIssuedCookieToken(response: Response, cookieName: string): string {
	const token = parseSetCookieHeader(response.headers.get("set-cookie") ?? "").get(
		cookieName,
	)?.value;
	if (!token) {
		throw new Error(`response did not deliver ${cookieName}`);
	}
	return token;
}
