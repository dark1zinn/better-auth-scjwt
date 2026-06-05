/**
 * User-facing plugin configuration. Optional fields receive defaults via
 * {@link ResolvedScjwtOptions}.
 */
export interface ScjwtOptions {
	/**
	 * Cryptographic key used to sign and verify HS256 JWT tokens.
	 */
	jwtSecret: string;
	/**
	 * Fully qualified URL of the token issuer authority (maps to JWT `iss`).
	 */
	issuer: string;
	/**
	 * JWT and session validity window in seconds.
	 * @default 3600
	 */
	expiresInSeconds?: number;
	/**
	 * HTTP-only cookie name when `tokenPlacement` is `"cookie"`.
	 * @default "auth-token"
	 */
	cookieName?: string;
	/**
	 * Transport strategy for the session JWT.
	 * - `"cookie"` — HTTP-only, Secure, SameSite=Lax
	 * - `"header"` — `set-auth-token` response header / `Authorization: Bearer`
	 * @default "cookie"
	 */
	tokenPlacement?: TokenPlacement;
	/**
	 * When enabled, actively used sessions receive an automatic JWT re-sign
	 * before expiry (20% lifetime threshold).
	 * @default false
	 */
	slidingSession?: boolean;
}

export type TokenPlacement = "cookie" | "header";

/**
 * Fully resolved configuration with all defaults applied.
 */
export interface ResolvedScjwtOptions {
	jwtSecret: string;
	issuer: string;
	expiresInSeconds: number;
	cookieName: string;
	tokenPlacement: TokenPlacement;
	slidingSession: boolean;
}

/**
 * Strict JWT payload contract (v1). No additional claims permitted.
 *
 * @see PLAN.md §2.1
 */
export interface ScjwtJwtPayload {
	/** Token issuer — mirrors `options.issuer`. */
	iss: string;
	/** Namespace-prefixed user id: `user:{userId}`. */
	sub: string;
	/** SHA-256 hex digest of client network/device constraints. */
	fp: string;
	/** Unix epoch seconds at issuance. */
	iat: number;
	/** Unix epoch seconds at cryptographic expiry. */
	exp: number;
	/** Database primary key of the backing session row. */
	sid: string;
}

/**
 * Pending sliding-session token queued during `onRequest` for delivery in `onResponse`.
 */
export interface PendingRefresh {
	token: string;
	placement: TokenPlacement;
}
