import { describe, expect, test } from "bun:test";
import type { AuthContext, Session, User } from "better-auth";
import { computeJwtExpiresInSeconds } from "../src/plugin/effective-expiry";
import { signJwtFromParts } from "../src/plugin/jwt";
import { loadSessionIntoContext } from "../src/plugin/session-bridge";
import {
	TEST_FINGERPRINT,
	TEST_ISSUER,
	TEST_JWT_SECRET,
	TEST_SESSION_ID,
	TEST_USER_ID,
} from "./helpers/fixtures";

function createMockContext(session: Session | null, user: User | null) {
	return {
		adapter: {
			findOne: async <T>(query: {
				model: string;
				where: Array<{ field: string; value: string }>;
			}): Promise<T | null> => {
				if (query.model === "session") {
					return session as T | null;
				}
				if (query.model === "user") {
					return user as T | null;
				}
				return null;
			},
		},
	} as AuthContext;
}

const testUser: User = {
	id: TEST_USER_ID,
	email: "drift@example.com",
	emailVerified: true,
	name: "Drift Test",
	createdAt: new Date(),
	updatedAt: new Date(),
};

describe("loadSessionIntoContext effective expiry", () => {
	test("rejects when JWT is valid but database session is expired", async () => {
		const nowSeconds = Math.floor(Date.now() / 1000);
		const jwtExp = nowSeconds + 3600;
		const expiredSession: Session = {
			id: TEST_SESSION_ID,
			userId: TEST_USER_ID,
			token: "session-token",
			expiresAt: new Date((nowSeconds - 60) * 1000),
			createdAt: new Date(),
			updatedAt: new Date(),
		};

		const context = createMockContext(expiredSession, testUser);
		const result = await loadSessionIntoContext(context, {
			iss: TEST_ISSUER,
			sub: `user:${TEST_USER_ID}`,
			fp: TEST_FINGERPRINT,
			iat: nowSeconds - 120,
			exp: jwtExp,
			sid: TEST_SESSION_ID,
		});

		expect(result?.response.status).toBe(401);
		const body = (await result?.response.json()) as { message?: string };
		expect(body.message).toBe("Session has expired.");
	});

	test("accepts when JWT exp matches the stricter database expiry", async () => {
		const nowSeconds = Math.floor(Date.now() / 1000);
		const dbExp = nowSeconds + 1800;
		const session: Session = {
			id: TEST_SESSION_ID,
			userId: TEST_USER_ID,
			token: "session-token",
			expiresAt: new Date(dbExp * 1000),
			createdAt: new Date(),
			updatedAt: new Date(),
		};

		const context = createMockContext(session, testUser);
		const result = await loadSessionIntoContext(context, {
			iss: TEST_ISSUER,
			sub: `user:${TEST_USER_ID}`,
			fp: TEST_FINGERPRINT,
			iat: nowSeconds,
			exp: dbExp,
			sid: TEST_SESSION_ID,
		});

		expect(result).toBeUndefined();
		expect(context.session).toBeDefined();
	});
});

describe("issuance TTL cap", () => {
	test("JWT exp does not exceed database session expiresAt", async () => {
		const issuedAt = Math.floor(Date.now() / 1000);
		const dbExp = issuedAt + 900;
		const configuredTtl = 3600;
		const expiresInSeconds = computeJwtExpiresInSeconds(
			issuedAt,
			configuredTtl,
			new Date(dbExp * 1000),
		);

		const token = await signJwtFromParts({
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			sessionId: TEST_SESSION_ID,
			expiresInSeconds,
			issuedAt,
		});

		const payload = JSON.parse(
			Buffer.from(token.split(".")[1]!, "base64url").toString(),
		) as { exp: number };

		expect(payload.exp).toBe(dbExp);
		expect(payload.exp).toBeLessThan(issuedAt + 3600);
	});
});
