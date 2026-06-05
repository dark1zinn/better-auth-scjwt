import { SignJWT } from "jose";
import type { ScjwtJwtPayload } from "./types";

const SUBJECT_PATTERN = /^user:[a-zA-Z0-9_-]+$/;
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;

export interface BuildJwtPayloadParams {
	issuer: string;
	userId: string;
	fingerprint: string;
	sessionId: string;
	expiresInSeconds: number;
	issuedAt?: number;
}

/**
 * Builds a v1 session-centric JWT payload with `iat` and `exp` derived from
 * `expiresInSeconds` (and optional `issuedAt`, defaulting to now).
 */
export function buildJwtPayload(params: BuildJwtPayloadParams): ScjwtJwtPayload {
	const iat = params.issuedAt ?? Math.floor(Date.now() / 1000);
	const payload: ScjwtJwtPayload = {
		iss: params.issuer,
		sub: `user:${params.userId}`,
		fp: params.fingerprint,
		iat,
		exp: iat + params.expiresInSeconds,
		sid: params.sessionId,
	};
	assertValidJwtPayload(payload);
	return payload;
}

/**
 * Signs a strict v1 payload with HS256.
 */
export async function signJwt(
	jwtSecret: string,
	payload: ScjwtJwtPayload,
): Promise<string> {
	assertValidJwtPayload(payload);

	const key = new TextEncoder().encode(jwtSecret);
	return new SignJWT({ ...payload })
		.setProtectedHeader({ alg: "HS256", typ: "JWT" })
		.sign(key);
}

/**
 * Signs a new token from session parts (builds payload, then signs).
 */
export async function signJwtFromParts(
	params: BuildJwtPayloadParams & { jwtSecret: string },
): Promise<string> {
	const { jwtSecret, ...payloadParams } = params;
	const payload = buildJwtPayload(payloadParams);
	return signJwt(jwtSecret, payload);
}

function assertValidJwtPayload(payload: ScjwtJwtPayload): void {
	if (!payload.iss.trim()) {
		throw new Error("[scjwt] JWT payload iss must be a non-empty string.");
	}

	if (!SUBJECT_PATTERN.test(payload.sub)) {
		throw new Error(
			'[scjwt] JWT payload sub must match "user:{userId}" (alphanumeric, _ and -).',
		);
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
