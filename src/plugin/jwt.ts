import type { SecretConfig } from "@better-auth/core";
import {
	decodeProtectedHeader,
	jwtVerify,
	SignJWT,
	type JWTPayload,
} from "jose";
import type { ScjwtJwtPayload } from "./types";

const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const CORE_CLAIMS: Record<string, true> = {
	iss: true,
	sub: true,
	fp: true,
	iat: true,
	exp: true,
	sid: true,
};

export type ScjwtSecretConfig = string | SecretConfig;

export interface VerifyJwtParams {
	token: string;
	secretConfig: ScjwtSecretConfig;
	issuer: string;
}

export interface BuildJwtPayloadParams {
	issuer: string;
	userId: string;
	fingerprint: string;
	sessionId: string;
	expiresAt: number;
	issuedAt?: number;
}

export function buildJwtPayload(params: BuildJwtPayloadParams): ScjwtJwtPayload {
	const iat = params.issuedAt ?? Math.floor(Date.now() / 1000);
	const payload: ScjwtJwtPayload = {
		iss: params.issuer,
		sub: `user:${params.userId}`,
		fp: params.fingerprint,
		iat,
		exp: params.expiresAt,
		sid: params.sessionId,
	};
	assertValidJwtPayload(payload);
	return payload;
}

export async function signJwt(
	secretConfig: ScjwtSecretConfig,
	payload: ScjwtJwtPayload,
): Promise<string> {
	assertValidJwtPayload(payload);
	const signing = getSigningSecret(secretConfig);
	const protectedHeader: { alg: "HS256"; typ: "JWT"; kid?: string } = {
		alg: "HS256",
		typ: "JWT",
	};
	if (signing.kid !== undefined) {
		protectedHeader.kid = signing.kid;
	}
	return new SignJWT({ ...payload })
		.setProtectedHeader(protectedHeader)
		.sign(encodeSecret(signing.secret));
}

export async function signJwtFromParts(
	params: BuildJwtPayloadParams & { secretConfig: ScjwtSecretConfig },
): Promise<string> {
	const { secretConfig, ...payloadParams } = params;
	return signJwt(secretConfig, buildJwtPayload(payloadParams));
}

export async function verifyJwt(
	params: VerifyJwtParams,
): Promise<ScjwtJwtPayload> {
	const key = getVerificationSecret(params.secretConfig, params.token);
	let rawPayload: JWTPayload;
	try {
		const { payload } = await jwtVerify(params.token, encodeSecret(key), {
			algorithms: ["HS256"],
			issuer: params.issuer,
		});
		rawPayload = payload;
	} catch (error) {
		const message =
			error instanceof Error ? error.message : "JWT verification failed.";
		throw new Error(`[scjwt] ${message}`);
	}
	return parseJwtPayload(rawPayload);
}

export function parseJwtPayload(payload: JWTPayload): ScjwtJwtPayload {
	for (const key of Object.keys(payload)) {
		if (!CORE_CLAIMS[key]) {
			throw new Error(`[scjwt] unexpected JWT claim "${key}".`);
		}
	}
	const parsed: ScjwtJwtPayload = {
		iss: readStringClaim(payload, "iss"),
		sub: readStringClaim(payload, "sub"),
		fp: readStringClaim(payload, "fp"),
		iat: readIntegerClaim(payload, "iat"),
		exp: readIntegerClaim(payload, "exp"),
		sid: readStringClaim(payload, "sid"),
	};
	assertValidJwtPayload(parsed);
	return parsed;
}

function getSigningSecret(config: ScjwtSecretConfig): {
	secret: string;
	kid?: string;
} {
	if (typeof config === "string") {
		return { secret: config };
	}
	const secret = config.keys.get(config.currentVersion);
	if (!secret) {
		throw new Error("[scjwt] Better Auth current secret version is unavailable.");
	}
	return { secret, kid: String(config.currentVersion) };
}

function getVerificationSecret(
	config: ScjwtSecretConfig,
	token: string,
): string {
	const header = decodeProtectedHeader(token);
	if (typeof config === "string") {
		if (header.kid !== undefined) {
			throw new Error("[scjwt] unexpected JWT key id.");
		}
		return config;
	}
	if (typeof header.kid !== "string" || !/^\d+$/.test(header.kid)) {
		throw new Error("[scjwt] JWT key id is required for versioned secrets.");
	}
	const secret = config.keys.get(Number(header.kid));
	if (!secret) {
		throw new Error(`[scjwt] unknown JWT key id "${header.kid}".`);
	}
	return secret;
}

function encodeSecret(secret: string): Uint8Array {
	return new TextEncoder().encode(secret);
}

function readStringClaim(payload: JWTPayload, claim: string): string {
	const value = payload[claim];
	if (typeof value !== "string") {
		throw new Error(`[scjwt] JWT claim "${claim}" must be a string.`);
	}
	return value;
}

function readIntegerClaim(payload: JWTPayload, claim: string): number {
	const value = payload[claim];
	if (typeof value !== "number" || !Number.isInteger(value)) {
		throw new Error(`[scjwt] JWT claim "${claim}" must be an integer.`);
	}
	return value;
}

function assertValidJwtPayload(payload: ScjwtJwtPayload): void {
	if (!payload.iss.trim()) {
		throw new Error("[scjwt] JWT payload iss must be a non-empty string.");
	}
	if (!payload.sub.startsWith("user:") || payload.sub.length === 5) {
		throw new Error('[scjwt] JWT payload sub must match "user:{userId}".');
	}
	if (!FINGERPRINT_PATTERN.test(payload.fp)) {
		throw new Error(
			"[scjwt] JWT payload fp must be a 64-character lowercase hex SHA-256 digest.",
		);
	}
	if (
		!Number.isInteger(payload.iat) ||
		!Number.isInteger(payload.exp) ||
		payload.exp <= payload.iat
	) {
		throw new Error(
			"[scjwt] JWT payload iat and exp must be integers with exp > iat.",
		);
	}
	if (!payload.sid.trim()) {
		throw new Error("[scjwt] JWT payload sid must be a non-empty string.");
	}
}
