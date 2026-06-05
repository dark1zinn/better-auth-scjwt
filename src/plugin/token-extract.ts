import type { TokenPlacement } from "./types";

export interface ExtractTokenParams {
	tokenPlacement: TokenPlacement;
	cookieName: string;
	headers: Headers;
}

/**
 * Extracts a session JWT from the incoming request headers.
 *
 * Returns `null` when no token is present (caller should fall through).
 * Extraction source depends on `tokenPlacement`:
 * - `"cookie"` — `Cookie` header value for `cookieName`
 * - `"header"` — `Authorization: Bearer <token>`
 */
export function extractToken(params: ExtractTokenParams): string | null {
	if (params.tokenPlacement === "cookie") {
		return extractTokenFromCookie(params.headers, params.cookieName);
	}

	return extractBearerToken(params.headers.get("authorization"));
}

export function extractTokenFromRequest(
	request: Request,
	params: Omit<ExtractTokenParams, "headers">,
): string | null {
	return extractToken({ ...params, headers: request.headers });
}

function extractTokenFromCookie(
	headers: Headers,
	cookieName: string,
): string | null {
	const cookieHeader = headers.get("cookie");
	if (!cookieHeader) {
		return null;
	}

	return getCookieValue(cookieHeader, cookieName);
}

function getCookieValue(cookieHeader: string, name: string): string | null {
	for (const segment of cookieHeader.split(";")) {
		const trimmed = segment.trim();
		const separatorIndex = trimmed.indexOf("=");
		if (separatorIndex === -1) {
			continue;
		}

		const key = trimmed.slice(0, separatorIndex).trim();
		if (key !== name) {
			continue;
		}

		const rawValue = trimmed.slice(separatorIndex + 1).trim();
		if (!rawValue) {
			return null;
		}

		return decodeCookieValue(rawValue);
	}

	return null;
}

function decodeCookieValue(value: string): string {
	if (!value.includes("%")) {
		return value;
	}

	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

function extractBearerToken(authorization: string | null): string | null {
	if (!authorization) {
		return null;
	}

	const spaceIndex = authorization.indexOf(" ");
	if (spaceIndex === -1) {
		return null;
	}

	const scheme = authorization.slice(0, spaceIndex).trim();
	if (scheme.toLowerCase() !== "bearer") {
		return null;
	}

	const token = authorization.slice(spaceIndex + 1).trim();
	return token || null;
}
