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

	test("without a resolvable IP, strict mode binds only browser headers and ip-only binds nothing", async () => {
		for (const fingerprintMode of ["strict", "ip-only"] as const) {
			const auth = betterAuth({
				database: memoryAdapter(createMemoryDB()),
				baseURL: TEST_BASE_URL,
				secret: TEST_SECRET,
				emailAndPassword: { enabled: true },
				// getIP returns null, as in production when no trustworthy client IP is available.
				advanced: { ipAddress: { disableIpTracking: true } },
				plugins: [scjwt({ fingerprintMode })],
			});
			const issued = await signUpWithScjwt(auth, `${fingerprintMode}-no-ip@example.com`, {
				"user-agent": "browser-a",
				"x-forwarded-for": "203.0.113.20",
			});
			const otherIp = await requestSession(
				auth,
				createCookieHeaders(issued.cookieName, issued.token, {
					"user-agent": "browser-a",
					"x-forwarded-for": "198.51.100.7",
				}),
			);
			expect(otherIp.status).toBe(200);
			const otherBrowser = await requestSession(
				auth,
				createCookieHeaders(issued.cookieName, issued.token, {
					"user-agent": "browser-b",
					"sec-ch-ua-platform": '"Windows"',
					"x-forwarded-for": "198.51.100.7",
				}),
			);
			expect(otherBrowser.status).toBe(fingerprintMode === "strict" ? 401 : 200);
		}
	});

	test("binds IPv6 clients to the configured subnet", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			advanced: { ipAddress: { ipAddressHeaders: ["x-forwarded-for"], ipv6Subnet: 64 } },
			plugins: [scjwt({ fingerprintMode: "ip-only" })],
		});
		const issued = await signUpWithScjwt(auth, "ipv6-subnet@example.com", {
			"x-forwarded-for": "2001:db8:1:2::1",
		});
		const sameSubnet = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token, {
				"x-forwarded-for": "2001:db8:1:2:ffff:ffff:ffff:ffff",
			}),
		);
		expect(sameSubnet.status).toBe(200);
		const otherSubnet = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token, {
				"x-forwarded-for": "2001:db8:1:3::1",
			}),
		);
		expect(otherSubnet.status).toBe(401);
	});

	test("ignores multi-hop forwarded chains when no proxy is trusted", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			advanced: { ipAddress: { ipAddressHeaders: ["x-forwarded-for"] } },
			plugins: [scjwt({ fingerprintMode: "ip-only" })],
		});
		const issued = await signUpWithScjwt(auth, "untrusted-chain@example.com", {
			"x-forwarded-for": "203.0.113.20, 192.0.2.10",
		});
		// Neither chain yields a trustworthy client IP, so the IP cannot distinguish them.
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token, {
				"x-forwarded-for": "198.51.100.7, 192.0.2.99",
			}),
		);
		expect(response.status).toBe(200);
	});

	test("tokens issued by direct server calls are bound to the server's request context", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt({ tokenPlacement: "header" })],
		});
		const { headers } = await auth.api.signUpEmail({
			body: {
				name: "Server Issued",
				email: "server-issued@example.com",
				password: "correct-horse-battery-staple",
			},
			headers: new Headers({ "user-agent": "backend-service" }),
			returnHeaders: true,
		});
		const token = headers.get("set-auth-token") ?? "";
		const browser = await requestSession(
			auth,
			new Headers({ "user-agent": "browser", authorization: `Bearer ${token}` }),
		);
		expect(browser.status).toBe(401);
		const server = await requestSession(
			auth,
			new Headers({ "user-agent": "backend-service", authorization: `Bearer ${token}` }),
		);
		expect(server.status).toBe(200);
	});
});
