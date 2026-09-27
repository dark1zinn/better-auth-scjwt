import { describe, expect, test } from "bun:test";
import type { SecondaryStorage } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { scjwt } from "../src/plugin/index";
import {
	TEST_BASE_URL,
	TEST_SECRET,
	createMemoryDB,
} from "./helpers/native-auth";

function createSecondaryStorage(): SecondaryStorage {
	const values = new Map<string, string>();
	return {
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
			secondaryStorage: createSecondaryStorage(),
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
			secondaryStorage: createSecondaryStorage(),
			session: { storeSessionInDatabase: true },
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			plugins: [scjwt()],
		});
		await expect(auth.$context).resolves.toMatchObject({
			baseURL: `${TEST_BASE_URL}/api/auth`,
		});
	});
});
