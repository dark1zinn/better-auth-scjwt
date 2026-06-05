import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { computeFingerprint } from "../src/plugin/fingerprint";

const HEX_64 = /^[a-f0-9]{64}$/;

function expectedFingerprint(
	ip: string,
	ua: string,
	platform: string,
): string {
	return createHash("sha256")
		.update(JSON.stringify({ ip, ua, platform }))
		.digest("hex");
}

describe("computeFingerprint", () => {
	test("returns a 64-character lowercase hex digest", () => {
		const fingerprint = computeFingerprint("127.0.0.1", "Mozilla/5.0", "web");
		expect(fingerprint).toMatch(HEX_64);
		expect(fingerprint).toBe(fingerprint.toLowerCase());
	});

	test("is deterministic for the same inputs", () => {
		const inputs = ["10.0.0.1", "curl/8.0", "api"] as const;
		const first = computeFingerprint(...inputs);
		const second = computeFingerprint(...inputs);
		expect(first).toBe(second);
	});

	test("matches SHA-256 of JSON.stringify({ ip, ua, platform })", () => {
		const ip = "127.0.0.1";
		const ua = "Mozilla/5.0";
		const platform = "web";
		expect(computeFingerprint(ip, ua, platform)).toBe(
			expectedFingerprint(ip, ua, platform),
		);
	});

	test("changes when ip changes", () => {
		const ua = "Mozilla/5.0";
		const platform = "web";
		const baseline = computeFingerprint("127.0.0.1", ua, platform);
		expect(computeFingerprint("127.0.0.2", ua, platform)).not.toBe(baseline);
	});

	test("changes when user-agent changes", () => {
		const ip = "127.0.0.1";
		const platform = "web";
		const baseline = computeFingerprint(ip, "Mozilla/5.0", platform);
		expect(computeFingerprint(ip, "curl/8.0", platform)).not.toBe(baseline);
	});

	test("changes when platform changes", () => {
		const ip = "127.0.0.1";
		const ua = "Mozilla/5.0";
		const baseline = computeFingerprint(ip, ua, "web");
		expect(computeFingerprint(ip, ua, "mobile")).not.toBe(baseline);
	});
});
