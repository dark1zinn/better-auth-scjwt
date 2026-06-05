import { getIp } from "better-auth/api";

export interface RequestFingerprintInput {
	ip: string;
	ua: string;
	platform: string;
}

export function getRequestFingerprintInput(
	headers: Headers,
	options: Parameters<typeof getIp>[1],
): RequestFingerprintInput {
	const ip = getIp(headers, options) ?? "";
	const ua = headers.get("user-agent") ?? "";
	const platform =
		headers.get("sec-ch-ua-platform")?.replaceAll('"', "").trim() ?? "";

	return { ip, ua, platform };
}
