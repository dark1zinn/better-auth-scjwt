import { describe, expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { admin, testUtils } from "better-auth/plugins";
import { scjwt } from "../src/plugin/index";
import {
	STABLE_HEADERS,
	TEST_BASE_URL,
	TEST_SECRET,
	createCookieHeaders,
	createMemoryDB,
	mintScjwt,
	requestSession,
} from "./helpers/native-auth";

async function createAdminHarness() {
	const db = createMemoryDB();
	const auth = betterAuth({
		database: memoryAdapter(db),
		baseURL: TEST_BASE_URL,
		secret: TEST_SECRET,
		plugins: [
			testUtils(),
			admin({ adminUserIds: ["admin-user"] }),
			scjwt(),
		],
	});
	const context = await auth.$context;
	const adminUser = await context.test.saveUser(
		context.test.createUser({
			id: "admin-user",
			email: "admin@example.com",
		}),
	);
	const targetUser = await context.test.saveUser(
		context.test.createUser({
			id: "target-user",
			email: "target@example.com",
		}),
	);
	const adminLogin = await context.test.login({ userId: adminUser.id });
	const adminToken = await mintScjwt(context, adminLogin.session);
	const adminHeaders = createCookieHeaders(
		context.authCookies.sessionToken.name,
		adminToken,
	);
	return { auth, context, db, targetUser, adminHeaders };
}


describe("Better Auth admin revocation paths", () => {
	test("banUser deletes target sessions and rejects the SCJWT", async () => {
		const harness = await createAdminHarness();
		const targetLogin = await harness.context.test.login({
			userId: harness.targetUser.id,
		});
		const targetToken = await mintScjwt(
			harness.context,
			targetLogin.session,
		);
		await harness.auth.api.banUser({
			headers: harness.adminHeaders,
			body: { userId: harness.targetUser.id, banReason: "security test" },
		});
		const response = await requestSession(
			harness.auth,
			createCookieHeaders(
				harness.context.authCookies.sessionToken.name,
				targetToken,
			),
		);
		expect(response.status).toBe(401);
		expect(
			harness.db.session.some((session) => session.id === targetLogin.session.id),
		).toBe(false);
	});

	test("revokeUserSession deletes one backing row and rejects its SCJWT", async () => {
		const harness = await createAdminHarness();
		const targetLogin = await harness.context.test.login({
			userId: harness.targetUser.id,
		});
		const targetToken = await mintScjwt(
			harness.context,
			targetLogin.session,
		);
		await harness.auth.api.revokeUserSession({
			headers: harness.adminHeaders,
			body: { sessionToken: targetLogin.session.token },
		});
		const response = await requestSession(
			harness.auth,
			createCookieHeaders(
				harness.context.authCookies.sessionToken.name,
				targetToken,
			),
		);
		expect(response.status).toBe(401);
		expect(
			harness.db.session.some((session) => session.id === targetLogin.session.id),
		).toBe(false);
	});

	test("revokeUserSessions invalidates every target SCJWT", async () => {
		const harness = await createAdminHarness();
		const firstLogin = await harness.context.test.login({
			userId: harness.targetUser.id,
		});
		const firstToken = await mintScjwt(harness.context, firstLogin.session);
		const secondLogin = await harness.context.test.login({
			userId: harness.targetUser.id,
		});
		const secondToken = await mintScjwt(harness.context, secondLogin.session);
		await harness.auth.api.revokeUserSessions({
			headers: harness.adminHeaders,
			body: { userId: harness.targetUser.id },
		});
		for (const token of [firstToken, secondToken]) {
			const response = await requestSession(
				harness.auth,
				createCookieHeaders(
					harness.context.authCookies.sessionToken.name,
					token,
				),
			);
			expect(response.status).toBe(401);
		}
		expect(
			harness.db.session.filter(
				(session) => session.userId === harness.targetUser.id,
			),
		).toHaveLength(0);
	});
});
