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

export interface ScjwtJwtPayload {
	iss: string;
	sub: string;
	fp: string;
	iat: number;
	exp: number;
	sid: string;
	[key: string]: JsonValue;
}
