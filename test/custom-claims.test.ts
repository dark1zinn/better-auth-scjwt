import { describe, expect, test } from "bun:test";
import type { SecretConfig } from "@better-auth/core";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { parseSetCookieHeader } from "better-auth/cookies";
import { decodeProtectedHeader } from "jose";
import { scjwt } from "../src/plugin/index";
import {
	getCustomClaims,
	signJwtFromParts,
	validateCustomClaims,
	verifyJwt,
} from "../src/plugin/jwt";
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

const FINGERPRINT = "a".repeat(64);

function tokenParts(customClaims?: Record<string, never | string | number | boolean | null>) {
	const issuedAt = Math.floor(Date.now() / 1000);
	return {
		secretConfig: TEST_SECRET,
		issuer: TEST_BASE_URL,
		userId: "claims-user",
		fingerprint: FINGERPRINT,
		sessionId: "claims-session",
		expiresAt: issuedAt + 3600,
		remember: true,
		issuedAt,
		customClaims,
	};
}

describe("custom SCJWT claims", () => {
	test("runs the resolver at issuance and native refresh", async () => {
		const seen: Array<{ sessionId: string; email: string; hasRequest: boolean }> = [];
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			session: { updateAge: 0 },
			plugins: [
				scjwt({
					getCustomClaims: ({ session, user, request }) => {
						seen.push({
							sessionId: session.id,
							email: user.email,
							hasRequest: request instanceof Request,
						});
						return { role: "member", flags: ["read", true] };
					},
				}),
			],
		});
		const issued = await signUpWithScjwt(auth, "resolver@example.com");
		const initial = await verifyJwt({
			token: issued.token,
			secretConfig: TEST_SECRET,
			issuer: (await auth.$context).baseURL,
			allowCustomClaims: true,
		});
		expect(getCustomClaims(initial)).toEqual({
			role: "member",
			flags: ["read", true],
		});

		rowAt(db.session).updatedAt = new Date(0);
		const refreshed = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token),
		);
		expect(refreshed.status).toBe(200);
		const refreshedToken = parseSetCookieHeader(
			refreshed.headers.get("set-cookie") ?? "",
		).get(issued.cookieName)?.value;
		expect(refreshedToken?.split(".")).toHaveLength(3);
		// Issuance, verification of the presented token, and re-issuance on refresh.
		expect(seen).toHaveLength(3);
		expect(seen.every((entry) => entry.email === "resolver@example.com")).toBe(true);
		expect(seen.every((entry) => entry.hasRequest)).toBe(true);
	});

	test("rejects changed dynamic claims without deleting the session", async () => {
		let role = "member";
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt({ getCustomClaims: () => ({ role }) })],
		});
		const issued = await signUpWithScjwt(auth, "changed-claims@example.com");
		role = "admin";
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token),
		);
		expect(response.status).toBe(401);
		expect(db.session).toHaveLength(1);
	});

	test("authenticates claims whose numbers change representation through JSON", async () => {
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [
				scjwt({
					getCustomClaims: () => ({
						offset: -0,
						nested: { values: [-0, 1.5, { zero: -0 }] },
					}),
				}),
			],
		});
		const issued = await signUpWithScjwt(auth, "negative-zero@example.com");
		for (let attempt = 0; attempt < 2; attempt += 1) {
			const response = await requestSession(
				auth,
				createCookieHeaders(issued.cookieName, issued.token),
			);
			expect(response.status).toBe(200);
		}
		expect(db.session).toHaveLength(1);
	});

	test("rejects a changed numeric claim without deleting the session", async () => {
		let level = 1;
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt({ getCustomClaims: () => ({ limits: [level] }) })],
		});
		const issued = await signUpWithScjwt(auth, "changed-number@example.com");
		level = 2;
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token),
		);
		expect(response.status).toBe(401);
		expect(db.session).toHaveLength(1);
	});

	test("refuses to issue non-finite claims and delivers no credential", async () => {
		for (const value of [Number.NaN, Number.POSITIVE_INFINITY]) {
			const auth = betterAuth({
				database: memoryAdapter(createMemoryDB()),
				baseURL: TEST_BASE_URL,
				secret: TEST_SECRET,
				emailAndPassword: { enabled: true },
				plugins: [scjwt({ getCustomClaims: () => ({ score: value }) })],
			});
			const response = await auth.handler(
				new Request(`${TEST_BASE_URL}/api/auth/sign-up/email`, {
					method: "POST",
					headers: { ...STABLE_HEADERS, "content-type": "application/json" },
					body: JSON.stringify({
						name: "Non-finite",
						email: `non-finite-${String(value)}@example.com`,
						password: "correct-horse-battery-staple",
					}),
				}),
			);
			expect(response.status).toBe(500);
			expect(response.headers.get("set-auth-token")).toBeNull();
			const sessionCookie = parseSetCookieHeader(
				response.headers.get("set-cookie") ?? "",
			).get((await auth.$context).authCookies.sessionToken.name);
			expect(sessionCookie?.value ?? "").toBe("");
		}
	});

	test("keeps the default payload strict and accepts valid configured JSON", async () => {
		const token = await signJwtFromParts({
			...tokenParts({ role: "member", active: true, level: 2, empty: null }),
		});
		await expect(
			verifyJwt({
				token,
				secretConfig: TEST_SECRET,
				issuer: TEST_BASE_URL,
			}),
		).rejects.toThrow('unexpected JWT claim "role"');
		const verified = await verifyJwt({
			token,
			secretConfig: TEST_SECRET,
			issuer: TEST_BASE_URL,
			allowCustomClaims: true,
		});
		expect(getCustomClaims(verified)).toEqual({
			role: "member",
			active: true,
			level: 2,
			empty: null,
		});
	});

	test("treats own prototype names as custom claims without mutating result prototypes", async () => {
		const claims: Record<string, string> = {
			toString: "display",
			constructor: "factory",
		};
		Object.defineProperty(claims, "__proto__", {
			value: "prototype",
			enumerable: true,
			configurable: true,
			writable: true,
		});
		const token = await signJwtFromParts({
			...tokenParts(),
			customClaims: claims,
		});
		const verified = await verifyJwt({
			token,
			secretConfig: TEST_SECRET,
			issuer: TEST_BASE_URL,
			allowCustomClaims: true,
		});
		const extracted = getCustomClaims(verified);
		expect(Object.getPrototypeOf(extracted)).toBeNull();
		expect(Object.keys(extracted).sort()).toEqual([
			"__proto__",
			"constructor",
			"toString",
		]);
		expect(extracted["__proto__"]).toBe("prototype");
		expect(extracted["constructor"]).toBe("factory");
		expect(extracted["toString"]).toBe("display");
	});

	test("rejects reserved names, non-JSON values, excessive keys, size, and depth", () => {
		expect(() => validateCustomClaims({ iss: "override" })).toThrow("reserved");
		expect(() => validateCustomClaims({ aud: "override" })).toThrow("reserved");
		expect(() => validateCustomClaims({ value: Number.NaN })).toThrow("finite");
		expect(() => validateCustomClaims({ value: undefined })).toThrow("JSON values");
		expect(() => validateCustomClaims({ value: BigInt(1) })).toThrow("JSON values");
		expect(() => validateCustomClaims({ value: new Date() })).toThrow("plain JSON objects");
		expect(() =>
			validateCustomClaims(
				Object.fromEntries(Array.from({ length: 17 }, (_, index) => [`key${index}`, index])),
			),
		).toThrow("at most 16");
		expect(() => validateCustomClaims({ text: "é".repeat(600) })).toThrow("1024 UTF-8 bytes");

		let nested: unknown = "leaf";
		for (let index = 0; index < 9; index += 1) nested = { nested };
		expect(() => validateCustomClaims({ nested })).toThrow("8 nested containers");
	});

	test("accepts claims exactly at the count, size, and depth limits", () => {
		const sixteen = Object.fromEntries(
			Array.from({ length: 16 }, (_, index) => [`key${index}`, index]),
		);
		expect(() => validateCustomClaims(sixteen)).not.toThrow();

		// {"text":"…"} adds 11 bytes around the string.
		expect(() => validateCustomClaims({ text: "x".repeat(1013) })).not.toThrow();
		expect(() => validateCustomClaims({ text: "x".repeat(1014) })).toThrow(
			"1024 UTF-8 bytes",
		);
		// Multi-byte characters count by encoded size: {"t":"…"} adds 8 bytes, "é" is 2.
		expect(() => validateCustomClaims({ t: "é".repeat(508) })).not.toThrow();
		expect(() => validateCustomClaims({ t: `${"é".repeat(508)}x` })).toThrow(
			"1024 UTF-8 bytes",
		);

		let objects: unknown = "leaf";
		let arrays: unknown = "leaf";
		for (let index = 0; index < 8; index += 1) {
			objects = { nested: objects };
			arrays = [arrays];
		}
		expect(() => validateCustomClaims({ objects, arrays })).not.toThrow();
		expect(() => validateCustomClaims({ arrays: [arrays] })).toThrow(
			"8 nested containers",
		);
	});

	test("distinguishes cycles from repeated references", () => {
		const shared = { scope: "read" };
		expect(() =>
			validateCustomClaims({ first: shared, second: [shared, shared] }),
		).not.toThrow();
		const cyclic: Record<string, unknown> = {};
		cyclic.self = cyclic;
		expect(() => validateCustomClaims({ cyclic })).toThrow("cyclic");
		const cyclicArray: unknown[] = [];
		cyclicArray.push(cyclicArray);
		expect(() => validateCustomClaims({ cyclicArray })).toThrow("cyclic");
	});

	test("reserves every core and registered claim name", () => {
		for (const name of [
			"iss",
			"sub",
			"aud",
			"exp",
			"nbf",
			"iat",
			"jti",
			"fp",
			"sid",
			"remember",
		]) {
			expect(() => validateCustomClaims({ [name]: "override" })).toThrow("reserved");
		}
		// Reserved names are only reserved at the top level.
		expect(() => validateCustomClaims({ nested: { sid: "x", remember: true } })).not.toThrow();
	});

	test("round-trips nested prototype-named keys through a signed token", async () => {
		const inner = JSON.parse('{"__proto__":{"polluted":true},"constructor":"c"}') as Record<
			string,
			never
		>;
		const token = await signJwtFromParts({ ...tokenParts(), customClaims: { inner } });
		const verified = await verifyJwt({
			token,
			secretConfig: TEST_SECRET,
			issuer: TEST_BASE_URL,
			allowCustomClaims: true,
		});
		expect(getCustomClaims(verified)).toEqual({ inner });
		expect(({} as Record<string, unknown>).polluted).toBeUndefined();
	});

	test("signs with the current Better Auth secret version and verifies retained keys", async () => {
		const original: SecretConfig = {
			keys: new Map([[1, "old-secret-at-least-thirty-two-bytes-long"]]),
			currentVersion: 1,
		};
		const token = await signJwtFromParts({
			...tokenParts(),
			secretConfig: original,
		});
		expect(decodeProtectedHeader(token).kid).toBe("1");
		const rotated: SecretConfig = {
			keys: new Map([
				[2, "new-secret-at-least-thirty-two-bytes-long"],
				[1, "old-secret-at-least-thirty-two-bytes-long"],
			]),
			currentVersion: 2,
		};
		await expect(
			verifyJwt({ token, secretConfig: rotated, issuer: TEST_BASE_URL }),
		).resolves.toMatchObject({ sid: "claims-session" });
	});
});
