import { describe, expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { scjwt } from "../src/plugin/index";
import {
	createCookieHeaders,
	createMemoryDB,
	requestSession,
	signUpWithScjwt,
	TEST_BASE_URL,
	TEST_SECRET,
} from "./helpers/native-auth";

describe("fingerprint modes", () => {
	test("uses stable empty strict inputs when UA and platform are absent", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "missing-headers@example.com", {});
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token, {}),
		);
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			user: { email: "missing-headers@example.com" },
		});
	});

	for (const mismatch of [
		{
			name: "User-Agent",
			issued: { "user-agent": "agent-a", "sec-ch-ua-platform": '"Linux"' },
			requested: { "user-agent": "agent-b", "sec-ch-ua-platform": '"Linux"' },
		},
		{
			name: "platform",
			issued: { "user-agent": "agent-a", "sec-ch-ua-platform": '"Linux"' },
			requested: { "user-agent": "agent-a", "sec-ch-ua-platform": '"Windows"' },
		},
	]) {
		test(`strict mode rejects a ${mismatch.name} mismatch without terminating the session`, async () => {
			const db = createMemoryDB();
			const auth = betterAuth({
				database: memoryAdapter(db),
				baseURL: TEST_BASE_URL,
				secret: TEST_SECRET,
				emailAndPassword: { enabled: true },
				plugins: [scjwt()],
			});
			const issued = await signUpWithScjwt(
				auth,
				`${mismatch.name.toLowerCase()}-mismatch@example.com`,
				mismatch.issued,
			);
			const headers = createCookieHeaders(
				issued.cookieName,
				issued.token,
				mismatch.requested,
			);
			const response = await requestSession(auth, headers);
			expect(response.status).toBe(401);
			const matchingResponse = await requestSession(
				auth,
				createCookieHeaders(issued.cookieName, issued.token, mismatch.issued),
			);
			expect(matchingResponse.status).toBe(200);
		});
	}

	test("ip-only mode tolerates UA and platform changes", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			advanced: { ipAddress: { ipAddressHeaders: ["x-client-ip"] } },
			plugins: [scjwt({ fingerprintMode: "ip-only" })],
		});
		const issued = await signUpWithScjwt(auth, "ip-only@example.com", {
			"x-client-ip": "203.0.113.10",
			"user-agent": "agent-a",
			"sec-ch-ua-platform": '"Linux"',
		});
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token, {
				"x-client-ip": "203.0.113.10",
				"user-agent": "agent-b",
				"sec-ch-ua-platform": '"Windows"',
			}),
		);
		expect(response.status).toBe(200);
	});

	test("uses Better Auth trusted-proxy resolution without terminating on client IP change", async () => {
		const db = createMemoryDB();
		const auth = betterAuth({
			database: memoryAdapter(db),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			advanced: {
				ipAddress: {
					ipAddressHeaders: ["x-forwarded-for"],
					trustedProxies: ["192.0.2.10"],
				},
			},
			plugins: [scjwt({ fingerprintMode: "ip-only" })],
		});
		const issued = await signUpWithScjwt(auth, "proxy-ip@example.com", {
			"x-forwarded-for": "203.0.113.20, 192.0.2.10",
		});
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token, {
				"x-forwarded-for": "203.0.113.21, 192.0.2.10",
			}),
		);
		expect(response.status).toBe(401);
		const matchingResponse = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token, {
				"x-forwarded-for": "203.0.113.20, 192.0.2.10",
			}),
		);
		expect(matchingResponse.status).toBe(200);
	});
});
