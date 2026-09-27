import { getIP } from "better-auth/api";
import type { FingerprintMode } from "./types";

export interface RequestFingerprintInput {
	ip: string;
	ua: string;
	platform: string;
}

export function getRequestFingerprintInput(
	headers: Headers,
	options: Parameters<typeof getIP>[1],
	mode: FingerprintMode,
): RequestFingerprintInput {
	const ip = getIP(headers, options) ?? "";
	if (mode === "ip-only") {
		return { ip, ua: "", platform: "" };
	}
	const ua = headers.get("user-agent") ?? "";
	const platform =
		headers.get("sec-ch-ua-platform")?.replaceAll('"', "").trim() ?? "";
	return { ip, ua, platform };
}
