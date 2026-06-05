import { betterAuth, type AuthContext } from "better-auth";
import { memoryAdapter, type MemoryDB } from "better-auth/adapters/memory";
import { testUtils, type TestHelpers } from "better-auth/plugins";
import { scjwt } from "../../src/plugin/index";
import {
	TEST_ISSUER,
	TEST_JWT_SECRET,
} from "./fixtures";

/**
 * Test-only Better Auth instance with {@link testUtils} and {@link scjwt}.
 *
 * @see https://better-auth.com/docs/plugins/test-utils
 */
export function createTestAuth(memoryDB: MemoryDB = {}) {
	return betterAuth({
		database: memoryAdapter(memoryDB),
		secret: "test-auth-secret",
		baseURL: TEST_ISSUER,
		plugins: [
			testUtils(),
			scjwt({
				jwtSecret: TEST_JWT_SECRET,
				issuer: TEST_ISSUER,
			}),
		],
	});
}

export async function getTestContext(
	auth: ReturnType<typeof createTestAuth>,
): Promise<AuthContext> {
	return (await auth.$context) as unknown as AuthContext;
}

export async function getTestHelpers(
	auth: ReturnType<typeof createTestAuth>,
): Promise<TestHelpers> {
	const ctx = await auth.$context;
	return ctx.test;
}
