import { describe, test } from "bun:test";
import { getTestHelpers } from "./helpers/auth-test";
import {
	createClearTestAuth,
	expectScjwtCookieCleared,
	expectScjwtCookieNotCleared,
	expectScjwtHeaderCleared,
	getScjwtCookieName,
	seedCredentialUser,
} from "./helpers/revoke-test";

describe("SCJWT client clearing on sign-out and revoke", () => {
	test("signOut clears auth-token cookie", async () => {
		const auth = createClearTestAuth();
		const test = await getTestHelpers(auth);

		const user = await seedCredentialUser(auth, test, "clear-signout@example.com");
		const { headers } = await test.login({ userId: user.id });
		const cookieName = await getScjwtCookieName(auth);

		const result = await auth.api.signOut({
			headers,
			returnHeaders: true,
		});

		expectScjwtCookieCleared(result.headers, cookieName);
	});

	test("revokeSessions clears auth-token cookie", async () => {
		const auth = createClearTestAuth();
		const test = await getTestHelpers(auth);

		const user = await seedCredentialUser(
			auth,
			test,
			"clear-revoke-all@example.com",
		);
		const { headers } = await test.login({ userId: user.id });
		const cookieName = await getScjwtCookieName(auth);

		const result = await auth.api.revokeSessions({
			headers,
			returnHeaders: true,
		});

		expectScjwtCookieCleared(result.headers, cookieName);
	});

	test("revokeSession does not clear cookie when revoking another device", async () => {
		const auth = createClearTestAuth();
		const test = await getTestHelpers(auth);

		const user = await seedCredentialUser(
			auth,
			test,
			"clear-revoke-other-device@example.com",
		);
		const loginA = await test.login({ userId: user.id });
		const loginB = await test.login({ userId: user.id });
		const cookieName = await getScjwtCookieName(auth);

		const result = await auth.api.revokeSession({
			headers: loginA.headers,
			body: { token: loginB.token },
			returnHeaders: true,
		});

		expectScjwtCookieNotCleared(result.headers, cookieName);
	});

	test("revokeSession clears cookie when revoking the current session", async () => {
		const auth = createClearTestAuth();
		const test = await getTestHelpers(auth);

		const user = await seedCredentialUser(
			auth,
			test,
			"clear-revoke-current@example.com",
		);
		const { headers, token } = await test.login({ userId: user.id });
		const cookieName = await getScjwtCookieName(auth);

		const result = await auth.api.revokeSession({
			headers,
			body: { token },
			returnHeaders: true,
		});

		expectScjwtCookieCleared(result.headers, cookieName);
	});

	test("revokeOtherSessions does not clear the current session cookie", async () => {
		const auth = createClearTestAuth();
		const test = await getTestHelpers(auth);

		const user = await seedCredentialUser(
			auth,
			test,
			"clear-revoke-others@example.com",
		);
		const loginA = await test.login({ userId: user.id });
		await test.login({ userId: user.id });
		const cookieName = await getScjwtCookieName(auth);

		const result = await auth.api.revokeOtherSessions({
			headers: loginA.headers,
			returnHeaders: true,
		});

		expectScjwtCookieNotCleared(result.headers, cookieName);
	});

	test("signOut clears set-auth-token header in header placement mode", async () => {
		const auth = createClearTestAuth({}, { tokenPlacement: "header" });
		const test = await getTestHelpers(auth);

		const user = await seedCredentialUser(
			auth,
			test,
			"clear-signout-header@example.com",
		);
		const { headers } = await test.login({ userId: user.id });

		const result = await auth.api.signOut({
			headers,
			returnHeaders: true,
		});

		expectScjwtHeaderCleared(result.headers);
	});
});
