import { parseCookies } from "better-auth/cookies";
import type { TokenPlacement } from "./types";

export interface ExtractTokenParams {
	tokenPlacement: TokenPlacement;
	cookieName: string;
	headers: Headers;
}

export function extractToken(params: ExtractTokenParams): string | null {
	if (params.tokenPlacement === "cookie") {
		const cookieHeader = params.headers.get("cookie");
		if (!cookieHeader) {
			return null;
		}
		return parseCookies(cookieHeader).get(params.cookieName) ?? null;
	}
	return extractBearerToken(params.headers.get("authorization"));
}

function extractBearerToken(authorization: string | null): string | null {
	if (!authorization?.toLowerCase().startsWith("bearer ")) {
		return null;
	}
	const token = authorization.slice(7).trim();
	return token || null;
}
