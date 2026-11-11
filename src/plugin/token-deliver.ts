import type { BetterAuthCookies } from "@better-auth/core";
import {
	type CookieAttributes,
	parseSetCookieHeader,
	splitSetCookieHeader,
	toCookieOptions,
} from "better-auth/cookies";
import { serializeCookie } from "better-call";
import type { TokenPlacement } from "./types";

export const SET_AUTH_TOKEN_HEADER = "set-auth-token";

/**
 * Places the SCJWT in the configured transport: cookie placement replaces the
 * live native session-token cookie; header placement sets `set-auth-token`
 * and removes live native session cookies.
 */
export function deliverSessionToken(
	headers: Headers,
	token: string,
	tokenPlacement: TokenPlacement,
	authCookies: BetterAuthCookies,
): void {
	const setCookies = getSetCookieValues(headers);
	const nextCookies: string[] = [];

	for (const setCookie of setCookies) {
		const parsed = parseSingleSetCookie(setCookie);
		if (!parsed) {
			nextCookies.push(setCookie);
			continue;
		}
		const [name, attributes] = parsed;
		const live = isLiveCookie(attributes);

		if (
			tokenPlacement === "cookie" &&
			name === authCookies.sessionToken.name &&
			live
		) {
			nextCookies.push(
				serializeCookie(name, token, toCookieOptions(attributes)),
			);
			continue;
		}

		if (
			tokenPlacement === "header" &&
			live &&
			isHeaderOnlyNativeCookie(name, authCookies)
		) {
			continue;
		}
		nextCookies.push(setCookie);
	}

	replaceSetCookieValues(headers, nextCookies);
	if (tokenPlacement === "header") {
		headers.set(SET_AUTH_TOKEN_HEADER, token);
		exposeHeader(headers, SET_AUTH_TOKEN_HEADER);
	}
}

/**
 * Whether the effective (last) `Set-Cookie` for `name` in `headers` keeps the
 * cookie alive, as opposed to clearing it. Absent cookies are not live.
 */
export function hasLiveSetCookie(headers: Headers | undefined, name: string): boolean {
	if (!headers) {
		return false;
	}
	let live = false;
	for (const setCookie of getSetCookieValues(headers)) {
		const parsed = parseSingleSetCookie(setCookie);
		if (parsed?.[0] === name) {
			live = isLiveCookie(parsed[1]);
		}
	}
	return live;
}

/**
 * Drops pending live native session cookies (session token, session data and
 * its chunks, `dontRemember`) and any pending `set-auth-token`, without
 * emitting clearing cookies, so the client keeps whatever SCJWT it already
 * holds. Clearing instructions already in `headers` are kept.
 */
export function removePendingSessionTransport(
	headers: Headers,
	authCookies: BetterAuthCookies,
): void {
	const kept = getSetCookieValues(headers).filter((setCookie) => {
		const parsed = parseSingleSetCookie(setCookie);
		return !(parsed && isHeaderOnlyNativeCookie(parsed[0], authCookies) && isLiveCookie(parsed[1]));
	});
	replaceSetCookieValues(headers, kept);
	headers.delete(SET_AUTH_TOKEN_HEADER);
}

/** All `Set-Cookie` values, with a fallback for runtimes lacking `getSetCookie`. */
function getSetCookieValues(headers: Headers): string[] {
	const withGetSetCookie = headers as Headers & {
		getSetCookie?: () => string[];
	};
	return withGetSetCookie.getSetCookie?.() ??
		splitSetCookieHeader(headers.get("set-cookie") ?? "");
}

/** Replaces every `Set-Cookie` value in `headers`. */
function replaceSetCookieValues(headers: Headers, values: string[]): void {
	headers.delete("set-cookie");
	for (const value of values) {
		headers.append("set-cookie", value);
	}
}

/** Parses one `Set-Cookie` value into its name and attributes. */
function parseSingleSetCookie(
	setCookie: string,
): [string, CookieAttributes] | null {
	const first = parseSetCookieHeader(setCookie).entries().next();
	return first.done ? null : first.value;
}

/**
 * Whether a `Set-Cookie` keeps its cookie alive. An empty value is a clearing
 * instruction. Per RFC 6265 §5.3, `Max-Age` takes precedence over `Expires`
 * and a zero or negative `Max-Age` expires the cookie immediately.
 */
function isLiveCookie(attributes: {
	value: string;
	"max-age"?: number;
	expires?: Date;
}): boolean {
	if (!attributes.value) {
		return false;
	}
	if (attributes["max-age"] !== undefined) {
		return attributes["max-age"] > 0;
	}
	return !attributes.expires || attributes.expires.getTime() > Date.now();
}

/** Whether `name` is a native cookie that header placement must not deliver. */
export function isHeaderOnlyNativeCookie(
	name: string,
	authCookies: BetterAuthCookies,
): boolean {
	return (
		name === authCookies.sessionToken.name ||
		name === authCookies.dontRememberToken.name ||
		name === authCookies.sessionData.name ||
		name.startsWith(`${authCookies.sessionData.name}.`)
	);
}

/** Adds `headerName` to `Access-Control-Expose-Headers` exactly once. */
function exposeHeader(headers: Headers, headerName: string): void {
	const exposed = new Map<string, string>();
	for (const value of (headers.get("access-control-expose-headers") ?? "").split(",")) {
		const name = value.trim();
		if (name) {
			exposed.set(name.toLowerCase(), name);
		}
	}
	exposed.set(headerName.toLowerCase(), headerName);
	headers.set("access-control-expose-headers", [...exposed.values()].join(", "));
}
