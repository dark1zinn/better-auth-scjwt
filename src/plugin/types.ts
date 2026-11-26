import type { Awaitable, Session, User } from "better-auth";

export type JsonValue =
	| string
	| number
	| boolean
	| null
	| JsonValue[]
	| { [key: string]: JsonValue };

export interface ScjwtClaimContext {
	session: Session & Record<string, unknown>;
	user: User & Record<string, unknown>;
	request: Request | undefined;
}

/**
 * How a token is bound to the device that received it. Each request's IP
 * network, User-Agent, and `Sec-CH-UA-Platform` are compared with the
 * signals the token was issued for.
 */
export interface ScjwtFingerprintOptions {
	/**
	 * - `strict`: all three signals must match; any change signs the request out.
	 * - `dynamic`: the platform must match. A change of the IP network or the
	 *   User-Agent alone continues the session and re-issues the token for the
	 *   new value; both changing at once signs the request out.
	 * - `loose`: any change continues the session and re-issues the token;
	 *   session liveness and custom claims are still enforced.
	 *
	 * @default "strict"
	 */
	mode?: "strict" | "dynamic" | "loose";
	/**
	 * Leading IPv4 bits that identify the network, 0 to 32.
	 *
	 * @default 32 in `strict` mode, 24 otherwise
	 */
	ipv4Prefix?: number;
	/**
	 * Leading IPv6 bits that identify the network, 0 to 128. Better Auth's
	 * `advanced.ipAddress.ipv6Subnet` applies first, so the shorter of the
	 * two prefixes wins.
	 *
	 * @default 128 in `strict` mode, 48 otherwise
	 */
	ipv6Prefix?: number;
}

export interface ScjwtOptions {
	tokenPlacement?: "cookie" | "header";
	fingerprint?: ScjwtFingerprintOptions;
	getCustomClaims?: (
		context: ScjwtClaimContext,
	) => Awaitable<Record<string, JsonValue>>;
}

export type TokenPlacement = NonNullable<ScjwtOptions["tokenPlacement"]>;
export type FingerprintMode = NonNullable<ScjwtFingerprintOptions["mode"]>;

export interface ResolvedFingerprintOptions {
	mode: FingerprintMode;
	ipv4Prefix: number;
	ipv6Prefix: number;
}

export interface ResolvedScjwtOptions {
	tokenPlacement: TokenPlacement;
	fingerprint: ResolvedFingerprintOptions;
	getCustomClaims?: ScjwtOptions["getCustomClaims"];
}

/**
 * Keyed device-signal digests carried in the `fp` claim: 32 lowercase hex
 * characters each, for the IP, User-Agent, and platform.
 */
export type ScjwtFingerprint = {
	ip: string;
	ua: string;
	pf: string;
};

export interface ScjwtJwtPayload {
	iss: string;
	sub: string;
	fp: ScjwtFingerprint;
	iat: number;
	exp: number;
	sid: string;
	/** `false` when Better Auth issued the session with `rememberMe: false`. */
	remember: boolean;
	[key: string]: JsonValue;
}
