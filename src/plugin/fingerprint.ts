import { createHash } from "node:crypto";

const FINGERPRINT_HEX_LENGTH = 64;

/**
 * Deterministic SHA-256 hex digest of client network/device constraints.
 *
 * Computes `SHA-256(JSON.stringify({ ip, ua, platform }))` and returns a
 * 64-character lowercase hex string used as the JWT `fp` claim.
 */
export function computeFingerprint(
	ip: string,
	ua: string,
	platform: string,
): string {
	const payload = JSON.stringify({ ip, ua, platform });
	const digest = createHash("sha256").update(payload).digest("hex");

	if (digest.length !== FINGERPRINT_HEX_LENGTH) {
		throw new Error(
			`[scjwt] fingerprint digest must be ${FINGERPRINT_HEX_LENGTH} hex characters.`,
		);
	}

	return digest;
}
