const FINGERPRINT_HEX_LENGTH = 64;

export async function computeFingerprint(
	ip: string,
	ua: string,
	platform: string,
): Promise<string> {
	const payload = new TextEncoder().encode(JSON.stringify({ ip, ua, platform }));
	const digest = new Uint8Array(
		await globalThis.crypto.subtle.digest("SHA-256", payload),
	);
	let hex = "";
	for (const byte of digest) {
		hex += byte.toString(16).padStart(2, "0");
	}
	if (hex.length !== FINGERPRINT_HEX_LENGTH) {
		throw new Error(
			`[scjwt] fingerprint digest must be ${FINGERPRINT_HEX_LENGTH} hex characters.`,
		);
	}
	return hex;
}
