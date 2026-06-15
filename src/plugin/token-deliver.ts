import type { AuthContext } from "better-auth";
import type { CookieOptions } from "better-call";
import type { TokenPlacement } from "./types";

/** Response header used in `header` placement (matches Better Auth Bearer convention). */
export const SET_AUTH_TOKEN_HEADER = "set-auth-token";

export type CreateAuthCookie = AuthContext["createAuthCookie"];

export interface DeliverTokenParams {
	token: string;
	tokenPlacement: TokenPlacement;
	expiresInSeconds: number;
	cookieName: string;
	createAuthCookie: CreateAuthCookie;
}

export interface ClearTokenParams {
	tokenPlacement: TokenPlacement;
	cookieName: string;
	createAuthCookie: CreateAuthCookie;
}

/**
 * Resolves cookie name/attributes via Better Auth's `createAuthCookie` helper.
 */
export function resolveAuthCookie(
	createAuthCookie: CreateAuthCookie,
	cookieName: string,
	expiresInSeconds: number,
): ReturnType<CreateAuthCookie> {
	return createAuthCookie(cookieName, { maxAge: expiresInSeconds });
}

/**
 * Appends the session JWT to response headers (Set-Cookie or `set-auth-token`).
 */
export function applyTokenToHeaders(
	headers: Headers,
	params: DeliverTokenParams,
): void {
	if (params.tokenPlacement === "header") {
		headers.set(SET_AUTH_TOKEN_HEADER, params.token);
		return;
	}

	const cookie = resolveAuthCookie(
		params.createAuthCookie,
		params.cookieName,
		params.expiresInSeconds,
	);

	headers.append(
		"Set-Cookie",
		formatSetCookieHeader(cookie.name, params.token, cookie.attributes),
	);
}

/**
 * Clears the session JWT from response headers (expired Set-Cookie or removed `set-auth-token`).
 */
export function clearTokenFromHeaders(
	headers: Headers,
	params: ClearTokenParams,
): void {
	if (params.tokenPlacement === "header") {
		headers.delete(SET_AUTH_TOKEN_HEADER);
		return;
	}

	const cookie = params.createAuthCookie(params.cookieName, { maxAge: 0 });

	headers.append(
		"Set-Cookie",
		formatSetCookieHeader(cookie.name, "", cookie.attributes),
	);
}

/**
 * Returns true when a `Set-Cookie` value clears the named cookie (empty value, Max-Age=0).
 */
export function isClearingSetCookie(
	setCookie: string,
	cookieName: string,
): boolean {
	const name = getSetCookieName(setCookie);
	if (name !== cookieName) {
		return false;
	}

	const [nameValue] = setCookie.split(";");
	const trimmed = nameValue?.trim() ?? "";
	const separatorIndex = trimmed.indexOf("=");
	if (separatorIndex === -1) {
		return false;
	}

	const value = trimmed.slice(separatorIndex + 1);
	if (value !== "") {
		return false;
	}

	return /(?:^|;)\s*Max-Age=0(?:\s*;|$)/i.test(setCookie);
}

/**
 * Returns a new `Response` with the session JWT attached.
 */
export function deliverTokenToResponse(
	response: Response,
	params: DeliverTokenParams,
): Response {
	const headers = new Headers(response.headers);
	applyTokenToHeaders(headers, params);

	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

function formatSetCookieHeader(
	name: string,
	value: string,
	attributes: CookieOptions,
): string {
	const parts = [`${name}=${value}`];

	if (attributes.maxAge !== undefined) {
		parts.push(`Max-Age=${attributes.maxAge}`);
	}

	if (attributes.expires) {
		parts.push(`Expires=${attributes.expires.toUTCString()}`);
	}

	if (attributes.domain) {
		parts.push(`Domain=${attributes.domain}`);
	}

	if (attributes.path) {
		parts.push(`Path=${attributes.path}`);
	}

	if (attributes.httpOnly) {
		parts.push("HttpOnly");
	}

	if (attributes.secure) {
		parts.push("Secure");
	}

	if (attributes.sameSite) {
		parts.push(`SameSite=${formatSameSite(attributes.sameSite)}`);
	}

	return parts.join("; ");
}

function formatSameSite(
	sameSite: NonNullable<CookieOptions["sameSite"]>,
): string {
	if (typeof sameSite !== "string") {
		return "Lax";
	}

	const normalized = sameSite.toLowerCase();
	if (normalized === "lax" || normalized === "strict" || normalized === "none") {
		return normalized.charAt(0).toUpperCase() + normalized.slice(1);
	}

	return sameSite;
}

function getSetCookieName(setCookie: string): string | null {
	const [nameValue] = setCookie.split(";");
	const trimmed = nameValue?.trim();
	if (!trimmed) {
		return null;
	}

	const separatorIndex = trimmed.indexOf("=");
	if (separatorIndex === -1) {
		return null;
	}

	return trimmed.slice(0, separatorIndex).trim();
}
