import { describe, expect, setSystemTime, test } from "bun:test";
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
	type HeaderInput,
	type TestDB,
} from "./helpers/native-auth";

const PASSWORD = "correct-horse-battery-staple";
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const PLACEMENTS = ["cookie", "header"] as const;
type Placement = (typeof PLACEMENTS)[number];

function createAuth(
	db: TestDB,
	tokenPlacement: Placement,
	session?: { expiresIn?: number; updateAge?: number },
) {
	return betterAuth({
		database: memoryAdapter(db),
		baseURL: TEST_BASE_URL,
		secret: TEST_SECRET,
		emailAndPassword: { enabled: true },
		session: {
			...session,
			additionalFields: { deviceLabel: { type: "string", required: false } },
		},
		plugins: [scjwt({ tokenPlacement })],
	});
}

type Auth = ReturnType<typeof createAuth>;

async function post(
	auth: Auth,
	path: string,
	body: object,
	headers: HeaderInput = STABLE_HEADERS,
): Promise<Response> {
	const requestHeaders = new Headers(headers);
	requestHeaders.set("content-type", "application/json");
	requestHeaders.set("origin", TEST_BASE_URL);
	return auth.handler(
		new Request(`${TEST_BASE_URL}/api/auth${path}`, {
			method: "POST",
			headers: requestHeaders,
			body: JSON.stringify(body),
		}),
	);
}

async function issuedToken(auth: Auth, response: Response): Promise<string> {
	expect(response.status).toBe(200);
	const name = (await auth.$context).authCookies.sessionToken.name;
	const token =
		response.headers.get("set-auth-token") ??
		parseSetCookieHeader(response.headers.get("set-cookie") ?? "").get(name)?.value;
	if (!token) throw new Error("no SCJWT was issued");
	return token;
}

/** Presents only the SCJWT, as a header client or a cookie client without the native marker. */
async function tokenHeaders(auth: Auth, placement: Placement, token: string) {
	if (placement === "header") {
		return new Headers({ ...STABLE_HEADERS, authorization: `Bearer ${token}` });
	}
	return createCookieHeaders((await auth.$context).authCookies.sessionToken.name, token);
}

function sessionExpiry(db: TestDB): number {
	return new Date(rowAt(db.session).expiresAt).getTime();
}

async function withClock<T>(at: number, run: () => Promise<T>): Promise<T> {
	setSystemTime(new Date(at));
	try {
		return await run();
	} finally {
		setSystemTime();
	}
}

describe("rememberMe:false sessions", () => {
	for (const placement of PLACEMENTS) {
		for (const flow of ["sign-up", "sign-in"] as const) {
			test(`${placement} ${flow} keeps the native one-day expiry without sliding`, async () => {
				const db = createMemoryDB();
				const auth = createAuth(db, placement);
				const email = `${placement}-${flow}@example.com`;
				let response = await post(auth, "/sign-up/email", {
					name: "Nonpersistent",
					email,
					password: PASSWORD,
					rememberMe: flow === "sign-in",
				});
				if (flow === "sign-in") {
					await issuedToken(auth, response);
					db.session.length = 0;
					response = await post(auth, "/sign-in/email", {
						email,
						password: PASSWORD,
						rememberMe: false,
					});
				}
				const token = await issuedToken(auth, response);
				expect(decodeJwt(token).remember).toBe(false);
				const issuedExpiry = sessionExpiry(db);
				expect(Math.abs(issuedExpiry - Date.now() - DAY_MS)).toBeLessThan(60_000);
				expect((decodeJwt(token).exp ?? 0) * 1000).toBeLessThanOrEqual(issuedExpiry);

				const context = await auth.$context;
				const cookies = parseSetCookieHeader(response.headers.get("set-cookie") ?? "");
				if (placement === "cookie") {
					// A browser session cookie: no persistent lifetime attribute.
					expect(cookies.get(context.authCookies.sessionToken.name)?.["max-age"]).toBeUndefined();
				} else {
					expect(cookies.has(context.authCookies.dontRememberToken.name)).toBe(false);
				}

				for (const offset of [0, 2 * HOUR_MS]) {
					const session = await withClock(Date.now() + offset, async () =>
						requestSession(auth, await tokenHeaders(auth, placement, token)),
					);
					expect(session.status).toBe(200);
					expect(await session.json()).toMatchObject({ user: { email } });
					expect(session.headers.get("set-auth-token")).toBeNull();
					expect(
						parseSetCookieHeader(session.headers.get("set-cookie") ?? "").get(
							context.authCookies.sessionToken.name,
						),
					).toBeUndefined();
					expect(sessionExpiry(db)).toBe(issuedExpiry);
				}
			});
		}
	}

	test("remembered sessions still refresh and stay remembered", async () => {
		for (const placement of PLACEMENTS) {
			const db = createMemoryDB();
			const auth = createAuth(db, placement, { expiresIn: 3600, updateAge: 0 });
			const token = await issuedToken(
				auth,
				await post(auth, "/sign-up/email", {
					name: "Remembered",
					email: `${placement}-remembered@example.com`,
					password: PASSWORD,
				}),
			);
			expect(decodeJwt(token).remember).toBe(true);
			const before = sessionExpiry(db);
			const refreshed = await withClock(Date.now() + 2000, async () =>
				requestSession(auth, await tokenHeaders(auth, placement, token)),
			);
			const replacement = await issuedToken(auth, refreshed);
			expect(replacement).not.toBe(token);
			expect(decodeJwt(replacement).remember).toBe(true);
			expect(decodeJwt(replacement).sid).toBe(decodeJwt(token).sid);
			expect(sessionExpiry(db)).toBeGreaterThan(before);
		}
	});

	test("non-persistent tokens live as long as Better Auth's one-day session when expiresIn is shorter", async () => {
		for (const placement of PLACEMENTS) {
			const db = createMemoryDB();
			const auth = createAuth(db, placement, { expiresIn: 3600 });
			const email = `${placement}-short-nonpersistent@example.com`;
			const token = await issuedToken(
				auth,
				await post(auth, "/sign-up/email", {
					name: "Short",
					email,
					password: PASSWORD,
					rememberMe: false,
				}),
			);
			const sessionEnd = sessionExpiry(db);
			expect(Math.abs(sessionEnd - Date.now() - DAY_MS)).toBeLessThan(60_000);
			expect((decodeJwt(token).exp ?? 0) * 1000).toBe(Math.floor(sessionEnd / 1000) * 1000);
			// Past expiresIn, where Better Auth's native session is still valid and never refreshed.
			const later = await withClock(Date.now() + 2 * HOUR_MS, async () =>
				requestSession(auth, await tokenHeaders(auth, placement, token)),
			);
			expect(later.status).toBe(200);
			expect(await later.json()).toMatchObject({ user: { email } });
		}
	});

	test("remembered tokens stay capped at expiresIn", async () => {
		const auth = createAuth(createMemoryDB(), "header", { expiresIn: 3600 });
		const token = await issuedToken(
			auth,
			await post(auth, "/sign-up/email", {
				name: "Remembered Short",
				email: "remembered-short@example.com",
				password: PASSWORD,
			}),
		);
		const { iat = 0, exp = 0 } = decodeJwt(token);
		expect(exp - iat).toBe(3600);
	});

	test("a supplied dontRemember cookie cannot override the signed claim", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db, "header", { expiresIn: 3600, updateAge: 0 });
		const context = await auth.$context;
		// A validly signed native marker, as a cookie-mode browser would hold it.
		const cookieAuth = createAuth(createMemoryDB(), "cookie");
		const nonpersistent = await post(cookieAuth, "/sign-up/email", {
			name: "Marker Source",
			email: "marker-source@example.com",
			password: PASSWORD,
			rememberMe: false,
		});
		const marker = parseSetCookieHeader(nonpersistent.headers.get("set-cookie") ?? "").get(
			context.authCookies.dontRememberToken.name,
		)?.value;
		expect(marker).toBeTruthy();

		const token = await issuedToken(
			auth,
			await post(auth, "/sign-up/email", {
				name: "Remembered",
				email: "remembered-with-marker@example.com",
				password: PASSWORD,
			}),
		);
		const before = sessionExpiry(db);
		const headers = await tokenHeaders(auth, "header", token);
		headers.set(
			"cookie",
			`${context.authCookies.dontRememberToken.name}=${encodeURIComponent(marker ?? "")}`,
		);
		const refreshed = await withClock(Date.now() + 2000, async () =>
			requestSession(auth, headers),
		);
		expect(decodeJwt(await issuedToken(auth, refreshed)).remember).toBe(true);
		expect(sessionExpiry(db)).toBeGreaterThan(before);
	});

	test("session re-issuance inherits the nonpersistent policy", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db, "header");
		const token = await issuedToken(
			auth,
			await post(auth, "/sign-up/email", {
				name: "Inherited",
				email: "inherited@example.com",
				password: PASSWORD,
				rememberMe: false,
			}),
		);
		const updated = await post(
			auth,
			"/update-session",
			{ deviceLabel: "kiosk" },
			await tokenHeaders(auth, "header", token),
		);
		const replacement = await issuedToken(auth, updated);
		expect(decodeJwt(replacement).sid).toBe(decodeJwt(token).sid);
		expect(decodeJwt(replacement).remember).toBe(false);
	});

	test("a remembered sign-in replaces a nonpersistent browser session", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db, "cookie");
		const context = await auth.$context;
		const email = "false-to-true@example.com";
		const first = await post(auth, "/sign-up/email", {
			name: "Transition",
			email,
			password: PASSWORD,
			rememberMe: false,
		});
		const firstCookies = parseSetCookieHeader(first.headers.get("set-cookie") ?? "");
		const browserCookies = [
			context.authCookies.sessionToken.name,
			context.authCookies.dontRememberToken.name,
		]
			.map((name) => `${name}=${encodeURIComponent(firstCookies.get(name)?.value ?? "")}`)
			.join("; ");
		const second = await post(
			auth,
			"/sign-in/email",
			{ email, password: PASSWORD, rememberMe: true },
			{ ...STABLE_HEADERS, cookie: browserCookies },
		);
		const token = await issuedToken(auth, second);
		expect(decodeJwt(token).remember).toBe(true);
		const cookies = parseSetCookieHeader(second.headers.get("set-cookie") ?? "");
		expect(cookies.get(context.authCookies.dontRememberToken.name)?.value).toBe("");
		expect(cookies.get(context.authCookies.sessionToken.name)?.["max-age"]).toBeGreaterThan(0);
	});
});
