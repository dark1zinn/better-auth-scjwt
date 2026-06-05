import { describe, expect, test } from "bun:test";
import {
	DEFAULT_COOKIE_NAME,
	DEFAULT_EXPIRES_IN_SECONDS,
	DEFAULT_SLIDING_SESSION,
	DEFAULT_TOKEN_PLACEMENT,
} from "../src/plugin/constants";
import { resolveOptions } from "../src/plugin/resolve-options";
import type { ScjwtOptions } from "../src/plugin/types";

const validOptions: ScjwtOptions = {
	jwtSecret: "test-secret",
	issuer: "https://api.example.com",
};

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
});
