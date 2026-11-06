import { describe, expect, test } from "bun:test";
import type { SecondaryStorage } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { scjwt } from "../src/plugin/index";
import {
	TEST_BASE_URL,
	TEST_SECRET,
	createCookieHeaders,
	createMemoryDB,
	requestSession,
	signUpWithScjwt,
} from "./helpers/native-auth";

/** In-memory secondary storage plus its backing map, so tests can evict entries. */
function createSecondaryStorage(): {
	storage: SecondaryStorage;
	values: Map<string, string>;
} {
	const values = new Map<string, string>();
	const storage: SecondaryStorage = {
		get(key) {
			return values.get(key) ?? null;
		},
		getAndDelete(key) {
			const value = values.get(key) ?? null;
			values.delete(key);
			return value;
		},
		increment(key) {
			const value = Number(values.get(key) ?? "0") + 1;
			values.set(key, String(value));
			return value;
		},
		set(key, value) {
			values.set(key, value);
		},
		delete(key) {
			values.delete(key);
		},
	};
	return { storage, values };
}

describe("database-backed session invariant", () => {
	test("rejects SCJWT without a Better Auth database", async () => {
		const auth = betterAuth({
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			plugins: [scjwt()],
		});
		await expect(auth.$context).rejects.toThrow(
			"a Better Auth database is required",
		);
	});

	test("rejects secondary-storage-only sessions", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			secondaryStorage: createSecondaryStorage().storage,
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			plugins: [scjwt()],
		});
		await expect(auth.$context).rejects.toThrow(
			"secondaryStorage requires session.storeSessionInDatabase: true",
		);
	});

	test("accepts secondary storage when sessions remain database-backed", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			secondaryStorage: createSecondaryStorage().storage,
			session: { storeSessionInDatabase: true },
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			plugins: [scjwt()],
		});
		await expect(auth.$context).resolves.toMatchObject({
			baseURL: `${TEST_BASE_URL}/api/auth`,
		});
	});

	test("rejects a preserved database row once secondary storage drops the session", async () => {
		const db = createMemoryDB();
		const { storage, values } = createSecondaryStorage();
		const auth = betterAuth({
			database: memoryAdapter(db),
			secondaryStorage: storage,
			session: {
				storeSessionInDatabase: true,
				preserveSessionInDatabase: true,
			},
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "preserved-row@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		expect((await requestSession(auth, headers)).status).toBe(200);

		const [row] = db.session;
		expect(values.has(row.token)).toBe(true);
		values.delete(row.token);
		expect(db.session).toHaveLength(1);
		expect(new Date(row.expiresAt).getTime()).toBeGreaterThan(Date.now());

		const response = await requestSession(auth, headers);
		expect(response.status).toBe(401);
	});
});
