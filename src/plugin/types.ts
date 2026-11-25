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

export interface ScjwtOptions {
	tokenPlacement?: "cookie" | "header";
	fingerprintMode?: "strict" | "ip-only";
	getCustomClaims?: (
		context: ScjwtClaimContext,
	) => Awaitable<Record<string, JsonValue>>;
}

export type TokenPlacement = NonNullable<ScjwtOptions["tokenPlacement"]>;
export type FingerprintMode = NonNullable<ScjwtOptions["fingerprintMode"]>;

export interface ResolvedScjwtOptions {
	tokenPlacement: TokenPlacement;
	fingerprintMode: FingerprintMode;
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
