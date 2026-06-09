import { describe, expect, test } from "bun:test";
import {
	TEST_PASSWORD,
	createRevokeOnRequestHandler,
	createRevokeTestAuth,
	expectScjwtAccepted,
	expectScjwtRejected,
	getRevokeTestContext,
	mintScjwtToken,
	runOnRequestWithToken,
	seedCredentialUser,
} from "./helpers/revoke-test";
import { getTestHelpers } from "./helpers/auth-test";

describe("Better Auth revoke paths invalidate SCJWT", () => {
	const handler = createRevokeOnRequestHandler();

	test("signOut deletes session row and rejects SCJWT", async () => {
		const auth = createRevokeTestAuth();
		const test = await getTestHelpers(auth);
		const context = await getRevokeTestContext(auth);

		const user = await seedCredentialUser(auth, test, "signout@example.com");
		const { session, headers } = await test.login({ userId: user.id });
		const token = await mintScjwtToken(context, session, user.id);

		await auth.api.signOut({ headers });

		const result = await runOnRequestWithToken(handler, context, token);
		await expectScjwtRejected(result);

		const deleted = await context.adapter.findOne({
			model: "session",
			where: [{ field: "id", value: session.id }],
		});
		expect(deleted).toBeNull();
	});

	test("revokeSession deletes target session and rejects its SCJWT", async () => {
		const auth = createRevokeTestAuth();
		const test = await getTestHelpers(auth);
		const context = await getRevokeTestContext(auth);

		const user = await seedCredentialUser(auth, test, "revoke-one@example.com");
		const loginA = await test.login({ userId: user.id });
		const loginB = await test.login({ userId: user.id });

		const tokenB = await mintScjwtToken(context, loginB.session, user.id);

		await auth.api.revokeSession({
			headers: loginA.headers,
			body: { token: loginB.token },
		});

		const result = await runOnRequestWithToken(handler, context, tokenB);
		await expectScjwtRejected(result);

		const deleted = await context.adapter.findOne({
			model: "session",
			where: [{ field: "id", value: loginB.session.id }],
		});
		expect(deleted).toBeNull();
	});

	test("revokeOtherSessions deletes other sessions but keeps current SCJWT valid", async () => {
		const auth = createRevokeTestAuth();
		const test = await getTestHelpers(auth);
		const context = await getRevokeTestContext(auth);

		const user = await seedCredentialUser(auth, test, "revoke-others@example.com");
		const loginA = await test.login({ userId: user.id });
		const loginB = await test.login({ userId: user.id });

		const tokenA = await mintScjwtToken(context, loginA.session, user.id);
		const tokenB = await mintScjwtToken(context, loginB.session, user.id);

		await auth.api.revokeOtherSessions({ headers: loginA.headers });

		const rejected = await runOnRequestWithToken(handler, context, tokenB);
		await expectScjwtRejected(rejected);

		const freshContext = await getRevokeTestContext(auth);
		const accepted = await runOnRequestWithToken(
			handler,
			freshContext,
			tokenA,
		);
		await expectScjwtAccepted(accepted, freshContext);

		const deletedB = await context.adapter.findOne({
			model: "session",
			where: [{ field: "id", value: loginB.session.id }],
		});
		expect(deletedB).toBeNull();

		const keptA = await context.adapter.findOne({
			model: "session",
			where: [{ field: "id", value: loginA.session.id }],
		});
		expect(keptA).not.toBeNull();
	});

	test("changePassword with revokeOtherSessions invalidates existing SCJWT", async () => {
		const auth = createRevokeTestAuth();
		const test = await getTestHelpers(auth);
		const context = await getRevokeTestContext(auth);

		const user = await seedCredentialUser(
			auth,
			test,
			"change-pw-revoke@example.com",
		);
		const { session, headers } = await test.login({ userId: user.id });
		const token = await mintScjwtToken(context, session, user.id);

		await auth.api.changePassword({
			headers,
			body: {
				currentPassword: TEST_PASSWORD,
				newPassword: "new-password-456",
				revokeOtherSessions: true,
			},
		});

		const result = await runOnRequestWithToken(handler, context, token);
		await expectScjwtRejected(result);

		const deleted = await context.adapter.findOne({
			model: "session",
			where: [{ field: "id", value: session.id }],
		});
		expect(deleted).toBeNull();
	});

	test("changePassword without revokeOtherSessions leaves SCJWT valid", async () => {
		const auth = createRevokeTestAuth();
		const test = await getTestHelpers(auth);
		const context = await getRevokeTestContext(auth);

		const user = await seedCredentialUser(
			auth,
			test,
			"change-pw-keep@example.com",
		);
		const { session, headers } = await test.login({ userId: user.id });
		const token = await mintScjwtToken(context, session, user.id);

		await auth.api.changePassword({
			headers,
			body: {
				currentPassword: TEST_PASSWORD,
				newPassword: "another-password-789",
			},
		});

		const result = await runOnRequestWithToken(handler, context, token);
		await expectScjwtAccepted(result, context);

		const kept = await context.adapter.findOne({
			model: "session",
			where: [{ field: "id", value: session.id }],
		});
		expect(kept).not.toBeNull();
	});
});
