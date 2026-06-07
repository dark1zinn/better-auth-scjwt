import type { AuthContext } from "better-auth";
import {
	DEFAULT_COOKIE_NAME,
	DEFAULT_EXPIRES_IN_SECONDS,
	DEFAULT_SLIDING_SESSION,
	DEFAULT_TOKEN_PLACEMENT,
} from "./constants";
import type {
	ResolvedScjwtOptions,
	ScjwtOptions,
	TokenPlacement,
} from "./types";

export const DATABASE_REQUIRED_ERROR =
	"[scjwt] database adapter is required; stateless mode is not supported.";

export function assertDatabaseConfigured(context: AuthContext): void {
	if (context.options.database === undefined) {
		throw new Error(DATABASE_REQUIRED_ERROR);
	}
}

export function createDatabaseRequiredInit() {
	return (context: AuthContext): void => {
		assertDatabaseConfigured(context);
	};
}

function assertNonEmptyString(value: string, field: string): string {
	const trimmed = value.trim();
	if (!trimmed) {
		throw new Error(`[scjwt] ${field} must be a non-empty string.`);
	}
	return trimmed;
}

function assertPositiveInteger(value: number, field: string): number {
	if (!Number.isFinite(value) || !Number.isInteger(value) || value <= 0) {
		throw new Error(`[scjwt] ${field} must be a positive integer.`);
	}
	return value;
}

function assertTokenPlacement(value: TokenPlacement): TokenPlacement {
	if (value !== "cookie" && value !== "header") {
		throw new Error(
			`[scjwt] tokenPlacement must be "cookie" or "header", received "${value}".`,
		);
	}
	return value;
}

export function resolveOptions(options: ScjwtOptions): ResolvedScjwtOptions {
	const jwtSecret = assertNonEmptyString(options.jwtSecret, "jwtSecret");
	const issuer = assertNonEmptyString(options.issuer, "issuer");

	const expiresInSeconds =
		options.expiresInSeconds === undefined
			? DEFAULT_EXPIRES_IN_SECONDS
			: assertPositiveInteger(options.expiresInSeconds, "expiresInSeconds");

	const cookieName =
		options.cookieName === undefined
			? DEFAULT_COOKIE_NAME
			: assertNonEmptyString(options.cookieName, "cookieName");

	const tokenPlacement =
		options.tokenPlacement === undefined
			? DEFAULT_TOKEN_PLACEMENT
			: assertTokenPlacement(options.tokenPlacement);

	const slidingSession = options.slidingSession ?? DEFAULT_SLIDING_SESSION;

	return {
		jwtSecret,
		issuer,
		expiresInSeconds,
		cookieName,
		tokenPlacement,
		slidingSession,
	};
}
