import type { SecretConfig } from "@better-auth/core";
import {
	decodeProtectedHeader,
	jwtVerify,
	SignJWT,
	type JWTPayload,
} from "jose";
import type { JsonValue, ScjwtJwtPayload } from "./types";

const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;
const MAX_CUSTOM_CLAIMS = 16;
const MAX_CUSTOM_CLAIMS_BYTES = 1024;
const MAX_JSON_CONTAINER_DEPTH = 8;
const CORE_CLAIMS: Record<string, true> = {
	iss: true,
	sub: true,
	fp: true,
	iat: true,
	exp: true,
	sid: true,
};
const RESERVED_CLAIMS: Record<string, true> = {
	...CORE_CLAIMS,
	aud: true,
	nbf: true,
	jti: true,
};

export type ScjwtSecretConfig = string | SecretConfig;
export type CustomClaims = Record<string, JsonValue>;

export interface VerifyJwtParams {
	token: string;
	secretConfig: ScjwtSecretConfig;
	issuer: string;
	allowCustomClaims?: boolean;
}

export interface BuildJwtPayloadParams {
	issuer: string;
	userId: string;
	fingerprint: string;
	sessionId: string;
	expiresAt: number;
	issuedAt?: number;
	customClaims?: CustomClaims;
}

export function buildJwtPayload(params: BuildJwtPayloadParams): ScjwtJwtPayload {
	const iat = params.issuedAt ?? Math.floor(Date.now() / 1000);
	const customClaims = params.customClaims ?? {};
	validateCustomClaims(customClaims);
	const payload: ScjwtJwtPayload = {
		iss: params.issuer,
		sub: `user:${params.userId}`,
		fp: params.fingerprint,
		iat,
		exp: params.expiresAt,
		sid: params.sessionId,
		...customClaims,
	};
	assertValidCorePayload(payload);
	return payload;
}

export async function signJwt(
	secretConfig: ScjwtSecretConfig,
	payload: ScjwtJwtPayload,
): Promise<string> {
	assertValidCorePayload(payload);
	validateCustomClaims(getCustomClaims(payload));
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
		.sign(new TextEncoder().encode(signing.secret));
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
		const { payload } = await jwtVerify(
			params.token,
			new TextEncoder().encode(key),
			{
				algorithms: ["HS256"],
				issuer: params.issuer,
			},
		);
		rawPayload = payload;
	} catch (error) {
		const message =
			error instanceof Error ? error.message : "JWT verification failed.";
		throw new Error(`[scjwt] ${message}`);
	}
	return parseJwtPayload(rawPayload, params.allowCustomClaims ?? false);
}

export function parseJwtPayload(
	payload: JWTPayload,
	allowCustomClaims = false,
): ScjwtJwtPayload {
	const customClaims: Record<string, unknown> = {};
	for (const key of Object.keys(payload)) {
		if (!CORE_CLAIMS[key]) {
			customClaims[key] = payload[key];
		}
	}
	if (!allowCustomClaims && Object.keys(customClaims).length > 0) {
		const [unexpected] = Object.keys(customClaims);
		throw new Error(`[scjwt] unexpected JWT claim "${unexpected}".`);
	}
	validateCustomClaims(customClaims);
	const parsed: ScjwtJwtPayload = {
		iss: readStringClaim(payload, "iss"),
		sub: readStringClaim(payload, "sub"),
		fp: readStringClaim(payload, "fp"),
		iat: readIntegerClaim(payload, "iat"),
		exp: readIntegerClaim(payload, "exp"),
		sid: readStringClaim(payload, "sid"),
		...(customClaims as CustomClaims),
	};
	assertValidCorePayload(parsed);
	return parsed;
}

export function getCustomClaims(payload: ScjwtJwtPayload): CustomClaims {
	const customClaims: CustomClaims = {};
	for (const [key, value] of Object.entries(payload)) {
		if (!CORE_CLAIMS[key]) {
			customClaims[key] = value;
		}
	}
	return customClaims;
}

export function validateCustomClaims(value: unknown): asserts value is CustomClaims {
	if (!isPlainObject(value)) {
		throw new Error("[scjwt] custom claims must be a plain JSON object.");
	}
	const keys = Object.keys(value);
	if (keys.length > MAX_CUSTOM_CLAIMS) {
		throw new Error(
			`[scjwt] custom claims may contain at most ${MAX_CUSTOM_CLAIMS} top-level keys.`,
		);
	}
	for (const key of keys) {
		if (RESERVED_CLAIMS[key]) {
			throw new Error(`[scjwt] custom claim "${key}" is reserved.`);
		}
		validateJsonValue(value[key], 0, new WeakSet<object>());
	}
	const serialized = JSON.stringify(value);
	if (new TextEncoder().encode(serialized).byteLength > MAX_CUSTOM_CLAIMS_BYTES) {
		throw new Error(
			`[scjwt] custom claims must not exceed ${MAX_CUSTOM_CLAIMS_BYTES} UTF-8 bytes.`,
		);
	}
}

export function jsonValuesEqual(left: JsonValue, right: JsonValue): boolean {
	if (Object.is(left, right)) {
		return true;
	}
	if (Array.isArray(left) || Array.isArray(right)) {
		if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) {
			return false;
		}
		return left.every((value, index) => jsonValuesEqual(value, right[index] as JsonValue));
	}
	if (isPlainObject(left) && isPlainObject(right)) {
		const leftKeys = Object.keys(left).sort();
		const rightKeys = Object.keys(right).sort();
		if (
			leftKeys.length !== rightKeys.length ||
			leftKeys.some((key, index) => key !== rightKeys[index])
		) {
			return false;
		}
		return leftKeys.every((key) =>
			jsonValuesEqual(left[key] as JsonValue, right[key] as JsonValue),
		);
	}
	return false;
}

function validateJsonValue(
	value: unknown,
	depth: number,
	ancestors: WeakSet<object>,
): asserts value is JsonValue {
	if (
		value === null ||
		typeof value === "string" ||
		typeof value === "boolean"
	) {
		return;
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) {
			throw new Error("[scjwt] custom claim numbers must be finite.");
		}
		return;
	}
	if (typeof value !== "object") {
		throw new Error("[scjwt] custom claims must contain JSON values only.");
	}
	if (depth >= MAX_JSON_CONTAINER_DEPTH) {
		throw new Error(
			`[scjwt] custom claims must not exceed ${MAX_JSON_CONTAINER_DEPTH} nested containers.`,
		);
	}
	if (ancestors.has(value)) {
		throw new Error("[scjwt] custom claims must not contain cyclic values.");
	}
	ancestors.add(value);
	if (Array.isArray(value)) {
		for (const item of value) {
			validateJsonValue(item, depth + 1, ancestors);
		}
	} else {
		if (!isPlainObject(value)) {
			throw new Error("[scjwt] custom claims must contain plain JSON objects only.");
		}
		for (const nested of Object.values(value)) {
			validateJsonValue(nested, depth + 1, ancestors);
		}
	}
	ancestors.delete(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (value === null || typeof value !== "object" || Array.isArray(value)) {
		return false;
	}
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
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

function assertValidCorePayload(payload: ScjwtJwtPayload): void {
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
