import { describe, expect, test } from "bun:test";
import {
	buildJwtPayload,
	signJwt,
	signJwtFromParts,
	verifyJwt,
} from "../src/plugin/jwt";
import {
	TEST_FINGERPRINT,
	TEST_ISSUER,
	TEST_JWT_SECRET,
	TEST_SESSION_ID,
	TEST_USER_ID,
} from "./helpers/fixtures";

describe("signJwt / verifyJwt", () => {
	test("round-trips via signJwtFromParts", async () => {
		const token = await signJwtFromParts({
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			sessionId: TEST_SESSION_ID,
			expiresInSeconds: 3600,
		});

		const verified = await verifyJwt({
			token,
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
		});

		expect(verified).toMatchObject({
			iss: TEST_ISSUER,
			sub: `user:${TEST_USER_ID}`,
			fp: TEST_FINGERPRINT,
			sid: TEST_SESSION_ID,
		});
		expect(verified.exp).toBeGreaterThan(verified.iat);
	});

	test("round-trips via buildJwtPayload and signJwt", async () => {
		const issuedAt = Math.floor(Date.now() / 1000);
		const payload = buildJwtPayload({
			issuer: TEST_ISSUER,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			sessionId: TEST_SESSION_ID,
			expiresInSeconds: 1800,
			issuedAt,
		});

		const token = await signJwt(TEST_JWT_SECRET, payload);
		const verified = await verifyJwt({
			token,
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
		});

		expect(verified).toEqual(payload);
	});

	test("rejects expired tokens", async () => {
		const issuedAt = Math.floor(Date.now() / 1000) - 7200;
		const token = await signJwtFromParts({
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			sessionId: TEST_SESSION_ID,
			expiresInSeconds: 3600,
			issuedAt,
		});

		await expect(
			verifyJwt({
				token,
				jwtSecret: TEST_JWT_SECRET,
				issuer: TEST_ISSUER,
			}),
		).rejects.toThrow("[scjwt]");
	});

	test("rejects tokens signed with a different secret", async () => {
		const token = await signJwtFromParts({
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			sessionId: TEST_SESSION_ID,
			expiresInSeconds: 3600,
		});

		await expect(
			verifyJwt({
				token,
				jwtSecret: "other-secret",
				issuer: TEST_ISSUER,
			}),
		).rejects.toThrow("[scjwt]");
	});

	test("rejects tokens with a different issuer", async () => {
		const token = await signJwtFromParts({
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			sessionId: TEST_SESSION_ID,
			expiresInSeconds: 3600,
		});

		await expect(
			verifyJwt({
				token,
				jwtSecret: TEST_JWT_SECRET,
				issuer: "https://other.example.com",
			}),
		).rejects.toThrow("[scjwt]");
	});

	test("rejects tampered tokens", async () => {
		const token = await signJwtFromParts({
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			sessionId: TEST_SESSION_ID,
			expiresInSeconds: 3600,
		});

		const tampered = `${token.slice(0, -1)}${token.at(-1) === "a" ? "b" : "a"}`;

		await expect(
			verifyJwt({
				token: tampered,
				jwtSecret: TEST_JWT_SECRET,
				issuer: TEST_ISSUER,
			}),
		).rejects.toThrow("[scjwt]");
	});

	test("rejects invalid payload shape at sign time", () => {
		expect(() =>
			buildJwtPayload({
				issuer: TEST_ISSUER,
				userId: "bad user id",
				fingerprint: TEST_FINGERPRINT,
				sessionId: TEST_SESSION_ID,
				expiresInSeconds: 3600,
			}),
		).toThrow('[scjwt] JWT payload sub must match "user:{userId}"');

		expect(() =>
			buildJwtPayload({
				issuer: TEST_ISSUER,
				userId: TEST_USER_ID,
				fingerprint: "not-a-valid-fingerprint",
				sessionId: TEST_SESSION_ID,
				expiresInSeconds: 3600,
			}),
		).toThrow(
			"[scjwt] JWT payload fp must be a 64-character lowercase hex SHA-256 digest.",
		);
	});
});
