import { describe, expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import {
	DEFAULT_COOKIE_NAME,
	DEFAULT_EXPIRES_IN_SECONDS,
	DEFAULT_SLIDING_SESSION,
	DEFAULT_TOKEN_PLACEMENT,
} from "../src/plugin/constants";
import { scjwt } from "../src/plugin/index";
import {
	DATABASE_REQUIRED_ERROR,
	assertDatabaseConfigured,
	resolveOptions,
} from "../src/plugin/resolve-options";
import type { ScjwtOptions } from "../src/plugin/types";
import { TEST_ISSUER, TEST_JWT_SECRET } from "./helpers/fixtures";

const validOptions: ScjwtOptions = {
	jwtSecret: "test-secret",
	issuer: "https://api.example.com",
};

const scjwtPlugin = scjwt({
	jwtSecret: TEST_JWT_SECRET,
	issuer: TEST_ISSUER,
});

describe("resolveOptions", () => {
	test("applies defaults for optional fields", () => {
		expect(resolveOptions(validOptions)).toEqual({
			jwtSecret: "test-secret",
			issuer: "https://api.example.com",
			expiresInSeconds: DEFAULT_EXPIRES_IN_SECONDS,
			cookieName: DEFAULT_COOKIE_NAME,
			tokenPlacement: DEFAULT_TOKEN_PLACEMENT,
			slidingSession: DEFAULT_SLIDING_SESSION,
		});
	});

	test("accepts explicit optional values", () => {
		expect(
			resolveOptions({
				...validOptions,
				expiresInSeconds: 7200,
				cookieName: "session-jwt",
				tokenPlacement: "header",
				slidingSession: true,
			}),
		).toEqual({
			jwtSecret: "test-secret",
			issuer: "https://api.example.com",
			expiresInSeconds: 7200,
			cookieName: "session-jwt",
			tokenPlacement: "header",
			slidingSession: true,
		});
	});

	test("trims jwtSecret and issuer", () => {
		expect(
			resolveOptions({
				jwtSecret: "  secret  ",
				issuer: "  https://api.example.com  ",
			}),
		).toMatchObject({
			jwtSecret: "secret",
			issuer: "https://api.example.com",
		});
	});

	test("rejects empty jwtSecret", () => {
		expect(() =>
			resolveOptions({ ...validOptions, jwtSecret: "" }),
		).toThrow("[scjwt] jwtSecret must be a non-empty string.");
	});

	test("rejects whitespace-only jwtSecret", () => {
		expect(() =>
			resolveOptions({ ...validOptions, jwtSecret: "   " }),
		).toThrow("[scjwt] jwtSecret must be a non-empty string.");
	});

	test("rejects empty issuer", () => {
		expect(() =>
			resolveOptions({ ...validOptions, issuer: "" }),
		).toThrow("[scjwt] issuer must be a non-empty string.");
	});

	test("rejects non-positive expiresInSeconds", () => {
		for (const value of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(() =>
				resolveOptions({ ...validOptions, expiresInSeconds: value }),
			).toThrow("[scjwt] expiresInSeconds must be a positive integer.");
		}
	});

	test("rejects empty cookieName", () => {
		expect(() =>
			resolveOptions({ ...validOptions, cookieName: "  " }),
		).toThrow("[scjwt] cookieName must be a non-empty string.");
	});

	test('rejects invalid tokenPlacement', () => {
		expect(() =>
			resolveOptions({
				...validOptions,
				tokenPlacement: "query" as ScjwtOptions["tokenPlacement"],
			}),
		).toThrow(
			'[scjwt] tokenPlacement must be "cookie" or "header", received "query".',
		);
	});

	test("fails fast when Better Auth is configured without a database", async () => {
		const auth = betterAuth({
			secret: "test-auth-secret",
			baseURL: TEST_ISSUER,
			plugins: [scjwtPlugin],
		});

		await expect(auth.$context).rejects.toThrow(DATABASE_REQUIRED_ERROR);
	});

	test("accepts an explicit database adapter", async () => {
		const auth = betterAuth({
			database: memoryAdapter({}),
			secret: "test-auth-secret",
			baseURL: TEST_ISSUER,
			plugins: [scjwtPlugin],
		});

		await expect(auth.$context).resolves.toBeDefined();
	});

	test("detects missing database configuration from auth context", () => {
		expect(() =>
			assertDatabaseConfigured({ options: {} } as Parameters<
				typeof assertDatabaseConfigured
			>[0]),
		).toThrow(DATABASE_REQUIRED_ERROR);
	});
});
