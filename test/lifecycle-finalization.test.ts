import { describe, expect, test } from "bun:test";
import type { BetterAuthPlugin } from "better-auth";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { APIError, createAuthMiddleware, isAPIError } from "better-auth/api";
import { parseSetCookieHeader, setSessionCookie } from "better-auth/cookies";
import { twoFactor } from "better-auth/plugins/two-factor";
import { kAPIErrorHeaderSymbol } from "better-call";
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

const PASSWORD = "correct-horse-battery-staple";
const PLACEMENTS = ["cookie", "header"] as const;

function signUpBody(email: string) {
	return { name: "Lifecycle User", email, password: PASSWORD };
}

function signUpRequest(email: string): Request {
	return new Request(`${TEST_BASE_URL}/api/auth/sign-up/email`, {
		method: "POST",
		headers: { ...STABLE_HEADERS, "content-type": "application/json" },
		body: JSON.stringify(signUpBody(email)),
	});
}

/** A plugin registered after SCJWT whose after-hook rejects sign-up. */
function lateDenial(): BetterAuthPlugin {
	return {
		id: "late-denial",
		hooks: {
			after: [
				{
					matcher: (ctx) => ctx.path === "/sign-up/email",
					handler: createAuthMiddleware(async () => {
						throw APIError.fromStatus("FORBIDDEN");
					}),
				},
			],
		},
	};
}

function bearerHeaders(token: string): Headers {
	return new Headers({ ...STABLE_HEADERS, authorization: `Bearer ${token}` });
}

/** A rejected credential (401) and an ignored one (null session) both leave the caller anonymous. */
async function expectUnauthenticated(response: Response): Promise<void> {
	if (response.status === 401) return;
	expect(response.status).toBe(200);
	expect(await response.json()).toBeNull();
}

describe("terminal SCJWT session finalizer", () => {
	test("delivers no usable credential when a later after-hook denies the request", async () => {
		for (const tokenPlacement of PLACEMENTS) {
			const db = createMemoryDB();
			const auth = betterAuth({
				database: memoryAdapter(db),
				baseURL: TEST_BASE_URL,
				secret: TEST_SECRET,
				emailAndPassword: { enabled: true },
				session: { cookieCache: { enabled: true } },
				plugins: [scjwt({ tokenPlacement }), lateDenial()],
			});
			const context = await auth.$context;
			const response = await auth.handler(
				signUpRequest(`${tokenPlacement}-late-denial@example.com`),
			);
			expect(response.status).toBe(403);
			expect(response.headers.get("set-auth-token")).toBeNull();
			const cookies = parseSetCookieHeader(response.headers.get("set-cookie") ?? "");
			for (const name of [
				context.authCookies.sessionToken.name,
				context.authCookies.sessionData.name,
			]) {
				expect(cookies.get(name)?.value).toBe("");
				expect(cookies.get(name)?.["max-age"]).toBe(0);
			}
			// The backing session belongs to Better Auth; only the transport is withheld.
			expect(db.session).toHaveLength(1);
		}
	});

	test("withholds the token from direct auth.api calls denied by a later hook", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt({ tokenPlacement: "header" }), lateDenial()],
		});
		const context = await auth.$context;
		const error: unknown = await auth.api
			.signUpEmail({
				body: signUpBody("api-late-denial@example.com"),
				headers: new Headers(STABLE_HEADERS),
				returnHeaders: true,
			})
			.then(
				() => null,
				(caught: unknown) => caught,
			);
		if (!isAPIError(error)) {
			throw new Error("expected the late hook to reject the sign-up");
		}
		expect(error.statusCode).toBe(403);
		const headers = (error as unknown as Record<symbol, Headers | undefined>)[
			kAPIErrorHeaderSymbol
		];
		expect(headers?.get("set-auth-token") ?? null).toBeNull();
		const cookies = parseSetCookieHeader(headers?.get("set-cookie") ?? "");
		expect(cookies.get(context.authCookies.sessionToken.name)?.value ?? "").toBe("");
	});

	test("issues to direct auth.api callers after every after-hook succeeds", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt({ tokenPlacement: "header" })],
		});
		const { headers } = await auth.api.signUpEmail({
			body: signUpBody("api-success@example.com"),
			headers: new Headers(STABLE_HEADERS),
			returnHeaders: true,
		});
		const token = headers.get("set-auth-token");
		expect(token?.split(".")).toHaveLength(3);
		const response = await requestSession(auth, bearerHeaders(token ?? ""));
		expect(await response.json()).toMatchObject({
			user: { email: "api-success@example.com" },
		});
	});

	test("issues nothing when a later hook withdraws the new session", async () => {
		for (const tokenPlacement of PLACEMENTS) {
			const auth = betterAuth({
				database: memoryAdapter(createMemoryDB()),
				baseURL: TEST_BASE_URL,
				secret: TEST_SECRET,
				emailAndPassword: { enabled: true },
				plugins: [
					scjwt({ tokenPlacement }),
					{
						id: "withdraw-session",
						hooks: {
							after: [
								{
									matcher: (ctx) => ctx.path === "/sign-up/email",
									handler: createAuthMiddleware(async (ctx) => {
										ctx.context.setNewSession(null);
									}),
								},
							],
						},
					},
				],
			});
			const context = await auth.$context;
			const response = await auth.handler(
				signUpRequest(`${tokenPlacement}-withdrawn@example.com`),
			);
			expect(response.status).toBe(200);
			expect(response.headers.get("set-auth-token")).toBeNull();
			const native = parseSetCookieHeader(response.headers.get("set-cookie") ?? "").get(
				context.authCookies.sessionToken.name,
			)?.value;
			// Whatever native cookie remains is not an SCJWT and cannot authenticate.
			expect(native?.split(".").length ?? 0).not.toBe(3);
			if (native) {
				const replay = await requestSession(
					auth,
					createCookieHeaders(context.authCookies.sessionToken.name, native),
				);
				await expectUnauthenticated(replay);
			}
		}
	});

	test("binds the token to a session that a later hook substitutes", async () => {
		for (const tokenPlacement of PLACEMENTS) {
			const replacementIds: string[] = [];
			const db = createMemoryDB();
			const auth = betterAuth({
				database: memoryAdapter(db),
				baseURL: TEST_BASE_URL,
				secret: TEST_SECRET,
				emailAndPassword: { enabled: true },
				plugins: [
					scjwt({ tokenPlacement }),
					{
						id: "replace-session",
						hooks: {
							after: [
								{
									matcher: (ctx) => ctx.path === "/sign-up/email",
									handler: createAuthMiddleware(async (ctx) => {
										const current = ctx.context.newSession;
										if (!current) return;
										const replacement =
											await ctx.context.internalAdapter.createSession(
												current.user.id,
											);
										replacementIds.push(replacement.id);
										await setSessionCookie(ctx, {
											session: replacement,
											user: current.user,
										});
									}),
								},
							],
						},
					},
				],
			});
			const email = `${tokenPlacement}-replaced@example.com`;
			const issued = await signUpWithScjwt(auth, email);
			expect(db.session).toHaveLength(2);
			expect(replacementIds).toHaveLength(1);
			expect(decodeJwt(issued.token).sid).toBe(replacementIds[0]);
			const headers = tokenPlacement === "cookie"
				? createCookieHeaders(issued.cookieName, issued.token)
				: bearerHeaders(issued.token);
			const response = await requestSession(auth, headers);
			expect(await response.json()).toMatchObject({
				session: { id: replacementIds[0] },
				user: { email },
			});
		}
	});

	test("keeps one plugin instance isolated across auth instances", async () => {
		const shared = scjwt({ tokenPlacement: "header" });
		const denied = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [shared, lateDenial()],
		});
		const plain = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: `${TEST_SECRET}-second-instance`,
			emailAndPassword: { enabled: true },
			plugins: [shared],
		});
		expect((await denied.handler(signUpRequest("shared-denied@example.com"))).status).toBe(
			403,
		);
		const issued = await signUpWithScjwt(plain, "shared-plain@example.com");
		expect(
			(await requestSession(plain, bearerHeaders(issued.token))).status,
		).toBe(200);
		// The token is bound to the issuing instance's secret.
		expect(
			(await requestSession(denied, bearerHeaders(issued.token))).status,
		).toBe(401);
		expect((await plain.$context).options.plugins?.map((plugin) => plugin.id)).toEqual([
			"scjwt",
			"scjwt-session-finalizer",
		]);
		expect(
			(await denied.$context).options.plugins?.map((plugin) => plugin.id),
		).toEqual(["scjwt", "late-denial", "scjwt-session-finalizer"]);
	});

	test("rejects requests before session creation when an after-hook is appended behind the finalizer", async () => {
		const db = createMemoryDB();
		const appender: BetterAuthPlugin = {
			id: "init-appender",
			init: () => ({
				options: {
					plugins: [
						{
							id: "appended-after",
							hooks: {
								after: [
									{
										matcher: () => true,
										handler: createAuthMiddleware(async () => {}),
									},
								],
							},
						},
					],
				},
			}),
		};
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt(), appender],
		});
		const response = await auth.handler(signUpRequest("appended@example.com"));
		expect(response.status).toBe(500);
		await expect(
			auth.api.signUpEmail({
				body: signUpBody("appended-api@example.com"),
				headers: new Headers(STABLE_HEADERS),
			}),
		).rejects.toThrow("[scjwt] session finalizer must run after all plugin after-hooks.");
		expect(db.user).toHaveLength(0);
		expect(db.session).toHaveLength(0);
	});

	test("rejects duplicate registration", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			plugins: [scjwt(), scjwt()],
		});
		await expect(auth.$context).rejects.toThrow("[scjwt] register scjwt() exactly once.");
	});

	test("header placement withholds the token while a two-factor challenge is pending", async () => {
		const codes = new Map<string, string>();
		const db = { ...createMemoryDB(), twoFactor: [] };
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [
				scjwt({ tokenPlacement: "header" }),
				twoFactor({
					otpOptions: {
						sendOTP: async ({ user, otp }) => {
							codes.set(user.id, otp);
						},
					},
				}),
			],
		});
		const email = "header-two-factor@example.com";
		const issued = await signUpWithScjwt(auth, email);
		const json = (headers: HeadersInit, cookie?: string) => {
			const result = new Headers(headers);
			result.set("content-type", "application/json");
			if (cookie) result.set("cookie", cookie);
			return result;
		};
		const post = (path: string, headers: Headers, body: object) =>
			auth.handler(
				new Request(`${TEST_BASE_URL}/api/auth${path}`, {
					method: "POST",
					headers,
					body: JSON.stringify(body),
				}),
			);
		const enabled = await post("/two-factor/enable", json(bearerHeaders(issued.token)), {
			password: PASSWORD,
			method: "otp",
		});
		expect(enabled.status).toBe(200);
		expect(enabled.headers.get("set-auth-token")?.split(".")).toHaveLength(3);

		const pending = await post("/sign-in/email", json(STABLE_HEADERS), {
			email,
			password: PASSWORD,
		});
		expect(pending.status).toBe(200);
		expect(await pending.json()).toMatchObject({ twoFactorRedirect: true });
		expect(pending.headers.get("set-auth-token")).toBeNull();
		// The challenge itself is a Better Auth cookie the client must return.
		const challenge = pending.headers
			.getSetCookie()
			.map((value) => value.split(";")[0] ?? "")
			.find((pair) => /two_factor=.+/.test(pair));
		expect(challenge).toBeDefined();

		expect(
			(await post("/two-factor/send-otp", json(STABLE_HEADERS, challenge), {})).status,
		).toBe(200);
		const verified = await post("/two-factor/verify-otp", json(STABLE_HEADERS, challenge), {
			code: codes.get(db.user[0]?.id ?? ""),
		});
		expect(verified.status).toBe(200);
		const token = verified.headers.get("set-auth-token");
		expect(token?.split(".")).toHaveLength(3);
		const session = await requestSession(auth, bearerHeaders(token ?? ""));
		expect(await session.json()).toMatchObject({ user: { email } });
	});
});
