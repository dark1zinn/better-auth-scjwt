import type { BetterAuthCookies, CookieAttributes } from "@better-auth/core";
import {
	parseSetCookieHeader,
	splitSetCookieHeader,
	toCookieOptions,
} from "better-auth/cookies";
import { serializeCookie } from "better-call";
import type { TokenPlacement } from "./types";

export const SET_AUTH_TOKEN_HEADER = "set-auth-token";

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

function getSetCookieValues(headers: Headers): string[] {
	const withGetSetCookie = headers as Headers & {
		getSetCookie?: () => string[];
	};
	return withGetSetCookie.getSetCookie?.() ??
		splitSetCookieHeader(headers.get("set-cookie") ?? "");
}

function replaceSetCookieValues(headers: Headers, values: string[]): void {
	headers.delete("set-cookie");
	for (const value of values) {
		headers.append("set-cookie", value);
	}
}

function parseSingleSetCookie(
	setCookie: string,
): [string, CookieAttributes] | null {
	const first = parseSetCookieHeader(setCookie).entries().next();
	return first.done ? null : first.value;
}

function isLiveCookie(attributes: {
	value: string;
	"max-age"?: number;
	expires?: Date;
}): boolean {
	if (!attributes.value || attributes["max-age"] === 0) {
		return false;
	}
	return !attributes.expires || attributes.expires.getTime() > Date.now();
}

function isHeaderOnlyNativeCookie(
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
