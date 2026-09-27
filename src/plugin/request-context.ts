import { getIP } from "better-auth/api";

export interface RequestFingerprintInput {
	ip: string;
	ua: string;
	platform: string;
}

export function getRequestFingerprintInput(
	headers: Headers,
	options: Parameters<typeof getIP>[1],
): RequestFingerprintInput {
	const ip = getIP(headers, options) ?? "";
	const ua = headers.get("user-agent") ?? "";
	const platform =
		headers.get("sec-ch-ua-platform")?.replaceAll('"', "").trim() ?? "";

	return { ip, ua, platform };
}
