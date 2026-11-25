import { normalizeIP } from "@better-auth/core/utils/ip";
import { getIP } from "better-auth/api";
import type { ResolvedFingerprintOptions } from "./types";

/** Raw device signals a fingerprint is computed from. */
export interface FingerprintSignals {
	/** Client network as `address/prefix`, or empty when no IP resolves. */
	ip: string;
	ua: string;
	platform: string;
}

/**
 * Device signals of a request: the network of Better Auth's resolved client
 * IP, the User-Agent, and `Sec-CH-UA-Platform`. Missing headers are empty
 * strings, so they stay deterministic.
 */
export function getFingerprintSignals(
	headers: Headers,
	options: Parameters<typeof getIP>[1],
	fingerprint: ResolvedFingerprintOptions,
): FingerprintSignals {
	const ip = getIP(headers, options);
	return {
		ip: ip ? ipNetwork(ip, fingerprint) : "",
		ua: headers.get("user-agent") ?? "",
		platform: headers.get("sec-ch-ua-platform")?.replaceAll('"', "").trim() ?? "",
	};
}

/** The network containing `ip` under the configured prefix lengths. */
function ipNetwork(
	ip: string,
	{ ipv4Prefix, ipv6Prefix }: ResolvedFingerprintOptions,
): string {
	const ipv4 = maskIPv4(ip, ipv4Prefix);
	if (ipv4 !== null) {
		return `${ipv4}/${ipv4Prefix}`;
	}
	return `${normalizeIP(ip, { ipv6Subnet: ipv6Prefix })}/${ipv6Prefix}`;
}

/** Masks a dotted-quad IPv4 address to `prefix` bits; `null` for anything else. */
function maskIPv4(ip: string, prefix: number): string | null {
	const octets = ip.split(".");
	if (octets.length !== 4 || !octets.every((octet) => /^\d{1,3}$/.test(octet))) {
		return null;
	}
	let address = 0;
	for (const octet of octets) {
		const value = Number(octet);
		if (value > 255) {
			return null;
		}
		address = address * 256 + value;
	}
	const hostBits = 2 ** (32 - prefix);
	const network = Math.floor(address / hostBits) * hostBits;
	return [24, 16, 8, 0].map((shift) => Math.floor(network / 2 ** shift) % 256).join(".");
}
