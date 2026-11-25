import type { FingerprintSignals } from "./request-context";
import type { ScjwtFingerprint } from "./types";

/** Bytes kept from each HMAC-SHA-256 digest (32 lowercase hex characters). */
const DIGEST_BYTES = 16;
/**
 * Prefix of every fingerprint MAC input. The NUL separators keep these inputs
 * disjoint from JWT signing input, and truncation to `DIGEST_BYTES` means a
 * digest can never stand in for a full HMAC signature (a JWT or a Better Auth
 * signed cookie) under the same secret.
 */
const DOMAIN = "better-auth-scjwt/fingerprint/v1\0";

const encoder = new TextEncoder();

/**
 * Keyed digests of the device signals, one per signal so a change can be
 * attributed to the IP, the User-Agent, or the platform. Each digest is an
 * HMAC-SHA-256 under `secret` truncated to 128 bits, so a token holder can
 * neither recover the signals (such as the client IP) nor compute digests
 * for other values.
 */
export async function computeFingerprint(
	secret: string,
	signals: FingerprintSignals,
): Promise<ScjwtFingerprint> {
	const key = await globalThis.crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const [ip, ua, pf] = await Promise.all([
		digestSignal(key, "ip", signals.ip),
		digestSignal(key, "ua", signals.ua),
		digestSignal(key, "pf", signals.platform),
	]);
	return { ip, ua, pf };
}

/** Truncated HMAC of one named signal, as lowercase hex. */
async function digestSignal(
	key: CryptoKey,
	name: keyof ScjwtFingerprint,
	value: string,
): Promise<string> {
	const mac = new Uint8Array(
		await globalThis.crypto.subtle.sign(
			"HMAC",
			key,
			encoder.encode(`${DOMAIN}${name}\0${value}`),
		),
	);
	let hex = "";
	for (const byte of mac.subarray(0, DIGEST_BYTES)) {
		hex += byte.toString(16).padStart(2, "0");
	}
	return hex;
}
