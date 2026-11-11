import { describe, expect, setSystemTime, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { parseSetCookieHeader } from "better-auth/cookies";
import { decodeJwt, decodeProtectedHeader, SignJWT, type JWTPayload } from "jose";
import { scjwt } from "../src/plugin/index";
import {
	STABLE_HEADERS,
	TEST_BASE_URL,
	TEST_SECRET,
	createMemoryDB,
	requestSession,
	signUpWithScjwt,
	type TestAuth,
	type TestDB,
} from "./helpers/native-auth";

const PASSWORD = "correct-horse-battery-staple";
const OTHER_SECRET = "a-different-secret-that-is-at-least-32-bytes";
const SECRET_V1 = "rotation-secret-version-one-at-least-32-bytes";
const SECRET_V2 = "rotation-secret-version-two-at-least-32-bytes";

type Claims = Record<string, unknown>;
type Auth = TestAuth;

function createAuth(
	db: TestDB,
	secret: { secret: string } | { secrets: Array<{ version: number; value: string }> } = {
		secret: TEST_SECRET,
	},
	expiresIn = 3600,
) {
	return betterAuth({
		database: memoryAdapter(db),
		baseURL: TEST_BASE_URL,
		...secret,
		emailAndPassword: { enabled: true },
		session: { expiresIn },
		plugins: [scjwt({ tokenPlacement: "header" })],
	});
}

function bearer(token: string): Headers {
	return new Headers({ ...STABLE_HEADERS, authorization: `Bearer ${token}` });
}

async function forge(
	claims: Claims,
	options: { alg?: string; secret?: string; header?: Record<string, unknown> } = {},
): Promise<string> {
	return new SignJWT(claims as JWTPayload)
		.setProtectedHeader({ alg: options.alg ?? "HS256", typ: "JWT", ...options.header })
		.sign(new TextEncoder().encode(options.secret ?? TEST_SECRET));
}

function unsigned(claims: Claims): string {
	const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
	return `${encode({ alg: "none", typ: "JWT" })}.${encode(claims)}.`;
}

function without(claims: Claims, key: string): Claims {
	const copy = { ...claims };
	delete copy[key];
	return copy;
}

async function signIn(auth: Auth, email: string): Promise<string> {
	const response = await auth.handler(
		new Request(`${TEST_BASE_URL}/api/auth/sign-in/email`, {
			method: "POST",
			headers: { ...STABLE_HEADERS, "content-type": "application/json" },
			body: JSON.stringify({ email, password: PASSWORD }),
		}),
	);
	const token = response.headers.get("set-auth-token");
	if (!token) throw new Error("sign-in did not issue an SCJWT");
	return token;
}

/**
 * Presents `token` and asserts a generic rejection that issues no credential,
 * returning the response body so callers can compare rejections.
 */
async function expectRejected(auth: Auth, token: string): Promise<unknown> {
	const response = await requestSession(auth, bearer(token));
	expect(response.status).toBe(401);
	expect(response.headers.get("set-auth-token")).toBeNull();
	const sessionCookie = parseSetCookieHeader(response.headers.get("set-cookie") ?? "").get(
		(await auth.$context).authCookies.sessionToken.name,
	);
	expect(sessionCookie?.value ?? "").toBe("");
	const text = await response.text();
	for (const secret of [TEST_SECRET, OTHER_SECRET, SECRET_V1, SECRET_V2]) {
		expect(text.includes(secret)).toBe(false);
	}
	return text ? JSON.parse(text) : null;
}

async function expectAuthenticated(auth: Auth, token: string, email: string) {
	const response = await requestSession(auth, bearer(token));
	expect(response.status).toBe(200);
	expect(await response.json()).toMatchObject({ user: { email } });
}

describe("SCJWT rejection boundaries", () => {
	test("rejects altered, foreign, and malformed tokens generically without touching sessions", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db);
		const email = "jwt-boundaries@example.com";
		const control = (await signUpWithScjwt(auth, email)).token;
		const claims = decodeJwt(control) as Claims;
		const now = Math.floor(Date.now() / 1000);

		// A faithful re-signing must authenticate, so every failure below is caused by its one change.
		await expectAuthenticated(auth, await forge(claims), email);

		const [header, payload, signature] = control.split(".");
		// Flip a leading character: the final base64url character of a 32-byte HMAC has
		// unused low bits, so changing it may leave the decoded signature unchanged.
		const flipped = `${signature?.startsWith("A") ? "B" : "A"}${signature?.slice(1)}`;
		const otherPayload = Buffer.from(
			JSON.stringify({ ...claims, sid: "attacker-chosen" }),
		).toString("base64url");

		const cases: Array<[string, string | Promise<string>]> = [
			["tampered signature", `${header}.${payload}.${flipped}`],
			["tampered payload", `${header}.${otherPayload}.${signature}`],
			["wrong secret", forge(claims, { secret: OTHER_SECRET })],
			["wrong issuer", forge({ ...claims, iss: "https://evil.example.com" })],
			["expired", forge({ ...claims, iat: now - 120, exp: now - 60 })],
			["alg none", unsigned(claims)],
			["HS384 with the same secret", forge(claims, { alg: "HS384" })],
			["unexpected claim without a resolver", forge({ ...claims, role: "admin" })],
			["string sid", forge({ ...claims, sid: 123 })],
			["string remember", forge({ ...claims, remember: "false" })],
			["fractional iat", forge({ ...claims, iat: (claims.iat as number) + 0.5 })],
			["fractional exp", forge({ ...claims, exp: (claims.exp as number) - 0.5 })],
			["malformed fingerprint", forge({ ...claims, fp: "abc" })],
			["other subject", forge({ ...claims, sub: "user:someone-else" })],
			["unknown session", forge({ ...claims, sid: "no-such-session" })],
			["not a JWT", "not-a-jwt"],
			...["iss", "sub", "fp", "iat", "exp", "sid", "remember"].map(
				(claim) =>
					[`missing ${claim}`, forge(without(claims, claim))] as [string, Promise<string>],
			),
		];

		const bodies = new Map<string, unknown>();
		for (const [label, token] of cases) {
			const body = await expectRejected(auth, await token);
			bodies.set(label, body);
		}
		const [first] = bodies.values();
		for (const [label, body] of bodies) {
			expect({ label, body }).toEqual({ label, body: first });
		}
		expect(db.session).toHaveLength(1);
		await expectAuthenticated(auth, control, email);
	});

	test("rejects a token at its exact expiry second", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db);
		const email = "exact-expiry@example.com";
		const claims = decodeJwt((await signUpWithScjwt(auth, email)).token) as Claims;
		const instant = Date.now();
		const second = Math.floor(instant / 1000);
		const token = await forge({ ...claims, iat: second - 60, exp: second });
		setSystemTime(new Date(second * 1000));
		try {
			await expectRejected(auth, token);
		} finally {
			setSystemTime();
		}
		expect(db.session).toHaveLength(1);
	});

	test("caps token expiry at the stored session and the configured lifetime", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db, { secret: TEST_SECRET }, 3600);
		const email = "expiry-cap@example.com";
		const control = (await signUpWithScjwt(auth, email)).token;
		const victim = await signIn(auth, email);
		const claims = decodeJwt(victim) as Claims;
		const row = db.session.find((session) => session.id === claims.sid);
		if (!row) throw new Error("missing victim session row");
		const now = Math.floor(Date.now() / 1000);

		// Beyond the configured lifetime while the row would still allow it.
		row.expiresAt = new Date((now + 10 * 3600) * 1000);
		await expectRejected(auth, await forge({ ...claims, iat: now, exp: now + 3600 + 60 }));
		// Beyond the stored session expiry while the lifetime would still allow it.
		row.expiresAt = new Date((now + 600) * 1000);
		await expectRejected(auth, await forge({ ...claims, iat: now, exp: now + 1200 }));
		// Within both caps the same session authenticates.
		await expectAuthenticated(auth, await forge({ ...claims, iat: now, exp: now + 300 }), email);

		expect(db.session).toHaveLength(2);
		await expectAuthenticated(auth, control, email);
	});
});

describe("versioned secret rotation", () => {
	test("accepts current and retained versions and rejects removed or invalid key ids", async () => {
		const db = createMemoryDB();
		const email = "rotation@example.com";
		const original = createAuth(db, { secrets: [{ version: 1, value: SECRET_V1 }] });
		const oldToken = (await signUpWithScjwt(original, email)).token;
		expect(decodeProtectedHeader(oldToken).kid).toBe("1");

		const rotated = createAuth(db, {
			secrets: [
				{ version: 2, value: SECRET_V2 },
				{ version: 1, value: SECRET_V1 },
			],
		});
		await expectAuthenticated(rotated, oldToken, email);
		const newToken = await signIn(rotated, email);
		expect(decodeProtectedHeader(newToken).kid).toBe("2");
		await expectAuthenticated(rotated, newToken, email);

		const claims = decodeJwt(newToken) as Claims;
		for (const header of [{ kid: "9" }, {}, { kid: "two" }, { kid: 2 }, { kid: "" }]) {
			await expectRejected(rotated, await forge(claims, { secret: SECRET_V2, header }));
		}
		// The key id selects the key; it cannot redirect verification to another version.
		await expectRejected(rotated, await forge(claims, { secret: SECRET_V2, header: { kid: "1" } }));

		const retired = createAuth(db, { secrets: [{ version: 2, value: SECRET_V2 }] });
		await expectRejected(retired, oldToken);
		await expectAuthenticated(retired, newToken, email);
	});

	test("a plain secret rejects tokens that carry a key id", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db);
		const email = "plain-kid@example.com";
		const control = (await signUpWithScjwt(auth, email)).token;
		expect(decodeProtectedHeader(control).kid).toBeUndefined();
		const claims = decodeJwt(control) as Claims;
		await expectRejected(auth, await forge(claims, { header: { kid: "1" } }));
		await expectAuthenticated(auth, control, email);
	});
});
