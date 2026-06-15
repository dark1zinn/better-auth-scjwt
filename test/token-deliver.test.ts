import { describe, expect, test } from "bun:test";
import type { CookieOptions } from "better-call";
import {
	SET_AUTH_TOKEN_HEADER,
	clearTokenFromHeaders,
	isClearingSetCookie,
} from "../src/plugin/token-deliver";

function mockCreateAuthCookie(
	name: string,
	attributes: CookieOptions,
) {
	return (cookieName: string, options?: { maxAge?: number }) => ({
		name: cookieName,
		attributes: {
			...attributes,
			maxAge: options?.maxAge ?? attributes.maxAge,
			expires:
				options?.maxAge === 0
					? new Date(0)
					: attributes.expires,
		},
	});
}

const baseAttributes: CookieOptions = {
	path: "/",
	httpOnly: true,
	secure: true,
	sameSite: "lax",
};

describe("clearTokenFromHeaders", () => {
	test("cookie mode appends clearing Set-Cookie with Max-Age=0", () => {
		const headers = new Headers();
		const createAuthCookie = mockCreateAuthCookie("auth-token", baseAttributes);

		clearTokenFromHeaders(headers, {
			tokenPlacement: "cookie",
			cookieName: "auth-token",
			createAuthCookie,
		});

		const setCookies =
			typeof headers.getSetCookie === "function"
				? headers.getSetCookie()
				: [headers.get("set-cookie") ?? ""];

		expect(setCookies).toHaveLength(1);
		expect(isClearingSetCookie(setCookies[0]!, "auth-token")).toBe(true);
		expect(setCookies[0]).toContain("Path=/");
		expect(setCookies[0]).toContain("HttpOnly");
		expect(setCookies[0]).toContain("Secure");
		expect(setCookies[0]).toContain("SameSite=Lax");
	});

	test("header mode removes set-auth-token", () => {
		const headers = new Headers();
		headers.set(SET_AUTH_TOKEN_HEADER, "jwt-token");
		const createAuthCookie = mockCreateAuthCookie("auth-token", baseAttributes);

		clearTokenFromHeaders(headers, {
			tokenPlacement: "header",
			cookieName: "auth-token",
			createAuthCookie,
		});

		expect(headers.has(SET_AUTH_TOKEN_HEADER)).toBe(false);
	});
});

describe("isClearingSetCookie", () => {
	test("returns true for empty value and Max-Age=0", () => {
		expect(
			isClearingSetCookie("auth-token=; Max-Age=0; Path=/; HttpOnly", "auth-token"),
		).toBe(true);
	});

	test("returns false for non-matching cookie name", () => {
		expect(
			isClearingSetCookie("other-token=; Max-Age=0; Path=/", "auth-token"),
		).toBe(false);
	});

	test("returns false when value is non-empty", () => {
		expect(
			isClearingSetCookie("auth-token=still-here; Max-Age=0; Path=/", "auth-token"),
		).toBe(false);
	});
});
