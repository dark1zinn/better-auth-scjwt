import { describe, expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import {
	DATABASE_REQUIRED_ERROR,
	assertDatabaseConfigured,
} from "../src/plugin/database-required";
import { scjwt } from "../src/plugin/index";
import { TEST_ISSUER, TEST_JWT_SECRET } from "./helpers/fixtures";

const scjwtPlugin = scjwt({
	jwtSecret: TEST_JWT_SECRET,
	issuer: TEST_ISSUER,
});

describe("database requirement", () => {
	test("fails fast when Better Auth is configured without a database", async () => {
		const auth = betterAuth({
			secret: "test-auth-secret",
			baseURL: TEST_ISSUER,
			plugins: [scjwtPlugin],
		});

		await expect(auth.$context).rejects.toThrow(DATABASE_REQUIRED_ERROR);
	});

	test("accepts an explicit database adapter", async () => {
		const auth = betterAuth({
			database: memoryAdapter({}),
			secret: "test-auth-secret",
			baseURL: TEST_ISSUER,
			plugins: [scjwtPlugin],
		});

		await expect(auth.$context).resolves.toBeDefined();
	});

	test("detects missing database configuration from auth context", () => {
		expect(() =>
			assertDatabaseConfigured({ options: {} } as Parameters<
				typeof assertDatabaseConfigured
			>[0]),
		).toThrow(DATABASE_REQUIRED_ERROR);
	});
});
