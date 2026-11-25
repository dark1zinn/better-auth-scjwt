import { describe, expect, setSystemTime, test } from "bun:test";
import { createHash } from "node:crypto";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { computeFingerprint } from "../src/plugin/fingerprint";
import { scjwt } from "../src/plugin/index";
import type { ScjwtFingerprint } from "../src/plugin/types";
import {
	TEST_BASE_URL,
	TEST_SECRET,
	createMemoryDB,
	requestSession,
	signUpWithScjwt,
	type TestDB,
} from "./helpers/native-auth";

const CLIENT_IP = "203.0.113.7";
const DEVICE = {
	"x-forwarded-for": CLIENT_IP,
	"user-agent": "privacy-browser/1.0",
	"sec-ch-ua-platform": '"Linux"',
};
const SIGNALS = { ip: CLIENT_IP, ua: "privacy-browser/1.0", platform: "Linux" };
const OTHER_SECRET = "a-different-secret-that-is-at-least-32-bytes";
const SECRET_V1 = "rotation-secret-version-one-at-least-32-bytes";
const SECRET_V2 = "rotation-secret-version-two-at-least-32-bytes";

function sha256(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

function bearer(token: string): Headers {
	return new Headers({ ...DEVICE, authorization: `Bearer ${token}` });
}

function createAuth(
	db: TestDB,
	secrets: Array<{ version: number; value: string }> | undefined = undefined,
) {
	return betterAuth({
		database: memoryAdapter(db),
		baseURL: TEST_BASE_URL,
		...(secrets ? { secrets } : { secret: TEST_SECRET }),
		emailAndPassword: { enabled: true },
		advanced: { ipAddress: { ipAddressHeaders: ["x-forwarded-for"] } },
		session: { expiresIn: 3600, updateAge: 0 },
		plugins: [scjwt({ tokenPlacement: "header" })],
	});
}

describe("keyed fingerprint digests", () => {
	test("an issued token cannot confirm a guessed client IP without the server secret", async () => {
		const auth = createAuth(createMemoryDB());
		const { token } = await signUpWithScjwt(auth, "privacy@example.com", DEVICE);
		const [, payloadPart] = token.split(".");
		const payloadText = Buffer.from(payloadPart ?? "", "base64url").toString("utf8");
		expect(payloadText.includes(CLIENT_IP)).toBe(false);
		// Unkeyed hashes of the signals, including the previous combined encoding,
		// are what a token holder could compute offline; none of them appear.
		const unkeyed = [
			sha256(JSON.stringify(SIGNALS)),
			sha256(CLIENT_IP),
			sha256(SIGNALS.ua),
			sha256(SIGNALS.platform),
		];
		for (const candidate of unkeyed) {
			expect(payloadText.includes(candidate.slice(0, 32))).toBe(false);
		}

		const { fp } = decodeJwt(token) as unknown as { fp: ScjwtFingerprint };
		expect(Object.keys(fp).sort()).toEqual(["ip", "pf", "ua"]);
		for (const digest of Object.values(fp)) {
			expect(digest).toMatch(/^[a-f0-9]{32}$/);
		}
		// Only the server secret reproduces the digests.
		expect(await computeFingerprint(TEST_SECRET, SIGNALS)).toEqual(fp);
		expect((await computeFingerprint(OTHER_SECRET, SIGNALS)).ip).not.toBe(fp.ip);
	});

	test("digests are deterministic per secret and change only for the signal that changed", async () => {
		const first = await computeFingerprint(TEST_SECRET, SIGNALS);
		expect(await computeFingerprint(TEST_SECRET, SIGNALS)).toEqual(first);

		const otherKey = await computeFingerprint(OTHER_SECRET, SIGNALS);
		expect([otherKey.ip === first.ip, otherKey.ua === first.ua, otherKey.pf === first.pf]).toEqual([
			false,
			false,
			false,
		]);

		const newAgent = await computeFingerprint(TEST_SECRET, { ...SIGNALS, ua: "other/2.0" });
		expect(newAgent).toEqual({ ...first, ua: newAgent.ua });
		expect(newAgent.ua).not.toBe(first.ua);
		// Equal values under different signal names still produce different digests.
		const same = await computeFingerprint(TEST_SECRET, { ip: "x", ua: "x", platform: "x" });
		expect(new Set(Object.values(same)).size).toBe(3);
	});

	test("rotating Better Auth's secret keeps tokens bound to the same device", async () => {
		const db = createMemoryDB();
		const email = "rotation-binding@example.com";
		const original = createAuth(db, [{ version: 1, value: SECRET_V1 }]);
		const { token } = await signUpWithScjwt(original, email, DEVICE);
		expect(decodeProtectedHeader(token).kid).toBe("1");

		const rotated = createAuth(db, [
			{ version: 2, value: SECRET_V2 },
			{ version: 1, value: SECRET_V1 },
		]);
		// Advance the mocked clock so the request refreshes the session without sleeping.
		setSystemTime(new Date(Date.now() + 2000));
		let refreshed: Response;
		try {
			refreshed = await requestSession(rotated, bearer(token));
		} finally {
			setSystemTime();
		}
		expect(await refreshed.clone().json()).toMatchObject({ user: { email } });
		const replacement = refreshed.headers.get("set-auth-token") ?? "";
		expect(decodeProtectedHeader(replacement).kid).toBe("2");
		expect(await (await requestSession(rotated, bearer(replacement))).json()).toMatchObject({
			user: { email },
		});
	});
});
