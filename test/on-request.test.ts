import { describe, expect, test } from "bun:test";
import { computeFingerprint } from "../src/plugin/fingerprint";
import { signJwtFromParts } from "../src/plugin/jwt";
import { createOnRequest } from "../src/plugin/on-request";
import { getRequestFingerprintInput } from "../src/plugin/request-context";
import { resolveOptions } from "../src/plugin/resolve-options";
import { DEFAULT_COOKIE_NAME } from "../src/plugin/constants";
import {
	createTestAuth,
	getTestContext,
	getTestHelpers,
} from "./helpers/auth-test";
import {
	TEST_ISSUER,
	TEST_JWT_SECRET,
} from "./helpers/fixtures";

const options = resolveOptions({
	jwtSecret: TEST_JWT_SECRET,
	issuer: TEST_ISSUER,
});

describe("createOnRequest", () => {
	test("falls through when no token is present", async () => {
		const auth = createTestAuth();
		const context = await getTestContext(auth);
		const handler = createOnRequest(options);

		const result = await handler(
			new Request(`${TEST_ISSUER}/api/protected`),
			context,
		);

		expect(result).toBeUndefined();
	});

	test("revokes the session and returns 401 on fingerprint mismatch", async () => {
		const auth = createTestAuth();
		const test = await getTestHelpers(auth);
		const context = await getTestContext(auth);
		const handler = createOnRequest(options);

		const user = test.createUser({ email: "fp-test@example.com" });
		await test.saveUser(user);
		const { session } = await test.login({ userId: user.id });

		const signHeaders = new Headers({ "user-agent": "Mozilla/5.0 TestAgent" });
		const { ip, ua, platform } = getRequestFingerprintInput(
			signHeaders,
			context.options,
		);
		const fingerprint = computeFingerprint(ip, ua, platform);

		const token = await signJwtFromParts({
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
			userId: user.id,
			fingerprint,
			sessionId: session.id,
			expiresInSeconds: options.expiresInSeconds,
		});

		const request = new Request(`${TEST_ISSUER}/api/protected`, {
			headers: {
				"user-agent": "curl/8.0 DifferentAgent",
				cookie: `${DEFAULT_COOKIE_NAME}=${token}`,
			},
		});

		const result = await handler(request, context);

		expect(result?.response.status).toBe(401);

		const body = (await result?.response.json()) as { message?: string };
		expect(body.message).toBe(
			"Machine fingerprint mismatch. Session revoked.",
		);

		const deletedSession = await context.adapter.findOne({
			model: "session",
			where: [{ field: "id", value: session.id }],
		});
		expect(deletedSession).toBeNull();
	});
});
