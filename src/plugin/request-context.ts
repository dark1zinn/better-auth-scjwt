import { getIP } from "better-auth/api";
import type { FingerprintMode } from "./types";

/** Raw device signals a fingerprint is computed from. */
export interface FingerprintSignals {
	ip: string;
	ua: string;
	platform: string;
}

/** Fingerprint inputs: Better Auth's resolved IP, plus browser headers in strict mode. */
export function getRequestFingerprintInput(
	headers: Headers,
	options: Parameters<typeof getIP>[1],
	mode: FingerprintMode,
): FingerprintSignals {
	const ip = getIP(headers, options) ?? "";
	if (mode === "ip-only") {
		return { ip, ua: "", platform: "" };
	}
	const ua = headers.get("user-agent") ?? "";
	const platform =
		headers.get("sec-ch-ua-platform")?.replaceAll('"', "").trim() ?? "";
	return { ip, ua, platform };
}
