import { describe, expect, test } from "bun:test";
import { betterAuth, type BetterAuthOptions, type BetterAuthPlugin } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthEndpoint } from "better-auth/api";
import { deleteSessionCookie, parseSetCookieHeader } from "better-auth/cookies";
import { decodeJwt } from "jose";
import { scjwt } from "../src/plugin/index";
import type { ScjwtFingerprintOptions } from "../src/plugin/types";
import {
	TEST_BASE_URL,
	TEST_SECRET,
	createCookieHeaders,
	createMemoryDB,
	expectSignedOut,
	requestSession,
	rowAt,
	signUpWithScjwt,
	type HeaderInput,
	type TestDB,
} from "./helpers/native-auth";

const PASSWORD = "correct-horse-battery-staple";
const PLACEMENTS = ["cookie", "header"] as const;
type Placement = (typeof PLACEMENTS)[number];

interface AuthSetup {
	placement?: Placement;
	fingerprint?: ScjwtFingerprintOptions;
	db?: TestDB;
	ipAddress?: NonNullable<BetterAuthOptions["advanced"]>["ipAddress"];
	plugins?: BetterAuthPlugin[];
}

function createAuth({ placement = "cookie", fingerprint, db, ipAddress, plugins = [] }: AuthSetup = {}) {
	return betterAuth({
		database: memoryAdapter(db ?? createMemoryDB()),
		baseURL: TEST_BASE_URL,
		secret: TEST_SECRET,
		emailAndPassword: { enabled: true },
		advanced: { ipAddress: ipAddress ?? { ipAddressHeaders: ["x-forwarded-for"] } },
		plugins: [scjwt({ tokenPlacement: placement, fingerprint }), ...plugins],
	});
}
type Auth = ReturnType<typeof createAuth>;

/** An endpoint that clears the session cookie but leaves the session live. */
const clearCookieFixture = {
	id: "clear-cookie-fixture",
	endpoints: {
		clearSessionCookie: createAuthEndpoint(
			"/clear-session-cookie",
			{ method: "POST" },
			async (ctx) => {
				deleteSessionCookie(ctx);
				return ctx.json({ cleared: true });
			},
		),
	},
} satisfies BetterAuthPlugin;

/** Request headers of a device: client IP, User-Agent, and platform. */
function device(ip: string, ua = "agent-a", platform = "Linux"): Record<string, string> {
	return {
		"x-forwarded-for": ip,
		"user-agent": ua,
		"sec-ch-ua-platform": `"${platform}"`,
	};
}

/** Presents `token` in `placement` from the given device. */
function present(
	placement: Placement,
	cookieName: string,
	token: string,
	from: HeaderInput,
): Headers {
	if (placement === "cookie") {
		return createCookieHeaders(cookieName, token, from);
	}
	const headers = new Headers(from);
	headers.set("authorization", `Bearer ${token}`);
	return headers;
}

/** The SCJWT a response delivered in `placement`, or `null` when none was. */
function deliveredToken(response: Response, placement: Placement, cookieName: string) {
	if (placement === "header") {
		return response.headers.get("set-auth-token");
	}
	const value = parseSetCookieHeader(response.headers.get("set-cookie") ?? "").get(
		cookieName,
	)?.value;
	return value || null;
}

interface Client {
	auth: Auth;
	placement: Placement;
	cookieName: string;
	email: string;
	token: string;
}

async function signUp(
	auth: Auth,
	placement: Placement,
	email: string,
	from: HeaderInput,
): Promise<Client> {
	const issued = await signUpWithScjwt(auth, email, from);
	return { auth, placement, cookieName: issued.cookieName, email, token: issued.token };
}

/** Reads the session with `token` from `from`. */
function read(client: Client, token: string, from: HeaderInput) {
	return requestSession(client.auth, present(client.placement, client.cookieName, token, from));
}

/** Asserts the request authenticated with its token unchanged (no replacement issued). */
async function expectMatch(client: Client, response: Response): Promise<void> {
	expect(response.status).toBe(200);
	expect(deliveredToken(response, client.placement, client.cookieName)).toBeNull();
	expect(await response.json()).toMatchObject({ user: { email: client.email } });
}

/**
 * Asserts the request authenticated and re-issued `presented` for the new
 * device without extending it; returns the replacement.
 */
async function expectRebind(
	client: Client,
	response: Response,
	presented: string,
): Promise<string> {
	expect(response.status).toBe(200);
	expect(await response.json()).toMatchObject({ user: { email: client.email } });
	const replacement = deliveredToken(response, client.placement, client.cookieName);
	expect(replacement?.split(".")).toHaveLength(3);
	const before = decodeJwt(presented);
	const after = decodeJwt(replacement ?? "");
	expect({ sid: after.sid, exp: after.exp, remember: after.remember }).toEqual({
		sid: before.sid,
		exp: before.exp,
		remember: before.remember,
	});
	expect(after.fp).not.toEqual(before.fp);
	return replacement ?? "";
}

describe("fingerprint options", () => {
	test("rejects the removed fingerprintMode option and invalid fingerprint settings", () => {
		expect(() => scjwt({ fingerprintMode: "ip-only" } as never)).toThrow(
			'[scjwt] fingerprintMode was replaced by fingerprint.mode ("strict", "dynamic" or "loose").',
		);
		expect(() => scjwt({ fingerprint: "dynamic" as never })).toThrow(
			"[scjwt] fingerprint must be an object",
		);
		expect(() => scjwt({ fingerprint: { mode: "ip-only" as never } })).toThrow(
			'[scjwt] fingerprint.mode must be "strict", "dynamic" or "loose".',
		);
		for (const ipv4Prefix of [-1, 33, 24.5, Number.NaN]) {
			expect(() => scjwt({ fingerprint: { ipv4Prefix } })).toThrow(
				"[scjwt] fingerprint.ipv4Prefix must be an integer from 0 to 32.",
			);
		}
		for (const ipv6Prefix of [-1, 129, 1.5]) {
			expect(() => scjwt({ fingerprint: { ipv6Prefix } })).toThrow(
				"[scjwt] fingerprint.ipv6Prefix must be an integer from 0 to 128.",
			);
		}
		for (const fingerprint of [
			{ mode: "strict", ipv4Prefix: 0, ipv6Prefix: 0 },
			{ mode: "dynamic", ipv4Prefix: 32, ipv6Prefix: 128 },
			{ mode: "loose" },
		] as const) {
			expect(() => scjwt({ fingerprint })).not.toThrow();
		}
	});

	test("each mode applies its IPv4 network default, and explicit prefixes override it", async () => {
		const cases = [
			{ fingerprint: undefined, expected: "signed out" },
			{ fingerprint: { ipv4Prefix: 24 }, expected: "match" },
			{ fingerprint: { mode: "dynamic" }, expected: "match" },
			{ fingerprint: { mode: "dynamic", ipv4Prefix: 32 }, expected: "rebind" },
		] as const;
		for (const [index, { fingerprint, expected }] of cases.entries()) {
			const client = await signUp(
				createAuth({ fingerprint }),
				"cookie",
				`ipv4-default-${index}@example.com`,
				device("203.0.113.10"),
			);
			// Same /24 network, different address.
			const response = await read(client, client.token, device("203.0.113.99"));
			if (expected === "signed out") {
				await expectSignedOut(response);
			} else if (expected === "match") {
				await expectMatch(client, response);
			} else {
				await expectRebind(client, response, client.token);
			}
		}
	});
});

describe("strict fingerprint mode", () => {
	test("uses stable empty inputs when User-Agent and platform are absent", async () => {
		const auth = createAuth();
		const issued = await signUpWithScjwt(auth, "missing-headers@example.com", {});
		const response = await requestSession(
			auth,
			createCookieHeaders(issued.cookieName, issued.token, {}),
		);
		expect(await response.json()).toMatchObject({
			user: { email: "missing-headers@example.com" },
		});
	});

	for (const change of [
		{ name: "IP", to: device("198.51.100.7") },
		{ name: "User-Agent", to: device("203.0.113.10", "agent-b") },
		{ name: "platform", to: device("203.0.113.10", "agent-a", "Windows") },
	]) {
		test(`signs out a ${change.name} change without ending the session`, async () => {
			for (const placement of PLACEMENTS) {
				const db = createMemoryDB();
				const client = await signUp(
					createAuth({ placement, db }),
					placement,
					`${placement}-strict-${change.name.toLowerCase()}@example.com`,
					device("203.0.113.10"),
				);
				await expectSignedOut(await read(client, client.token, change.to));
				expect(db.session).toHaveLength(1);
				await expectMatch(client, await read(client, client.token, device("203.0.113.10")));
			}
		});
	}

	test("uses Better Auth trusted-proxy resolution for the client IP", async () => {
		const client = await signUp(
			createAuth({
				ipAddress: { ipAddressHeaders: ["x-forwarded-for"], trustedProxies: ["192.0.2.10"] },
			}),
			"cookie",
			"proxy-ip@example.com",
			{ ...device("ignored"), "x-forwarded-for": "203.0.113.20, 192.0.2.10" },
		);
		await expectSignedOut(
			await read(client, client.token, {
				...device("ignored"),
				"x-forwarded-for": "203.0.113.21, 192.0.2.10",
			}),
		);
		await expectMatch(
			client,
			await read(client, client.token, {
				...device("ignored"),
				"x-forwarded-for": "203.0.113.20, 192.0.2.10",
			}),
		);
	});

	test("binds IPv6 clients within Better Auth's ipv6Subnet", async () => {
		const client = await signUp(
			createAuth({ ipAddress: { ipAddressHeaders: ["x-forwarded-for"], ipv6Subnet: 64 } }),
			"cookie",
			"ipv6-subnet@example.com",
			device("2001:db8:1:2::1"),
		);
		await expectMatch(
			client,
			await read(client, client.token, device("2001:db8:1:2:ffff:ffff:ffff:ffff")),
		);
		await expectSignedOut(await read(client, client.token, device("2001:db8:1:3::1")));
	});

	test("ignores multi-hop forwarded chains when no proxy is trusted", async () => {
		const client = await signUp(
			createAuth(),
			"cookie",
			"untrusted-chain@example.com",
			{ ...device("ignored"), "x-forwarded-for": "203.0.113.20, 192.0.2.10" },
		);
		// Neither chain yields a trustworthy client IP, so the IP cannot distinguish them.
		await expectMatch(
			client,
			await read(client, client.token, {
				...device("ignored"),
				"x-forwarded-for": "198.51.100.7, 192.0.2.99",
			}),
		);
	});

	test("without a resolvable IP, strict binds only browser headers and loose re-binds", async () => {
		for (const mode of ["strict", "loose"] as const) {
			const client = await signUp(
				createAuth({
					fingerprint: { mode },
					// getIP returns null, as in production when no trustworthy client IP is available.
					ipAddress: { disableIpTracking: true },
				}),
				"cookie",
				`${mode}-no-ip@example.com`,
				device("203.0.113.20", "browser-a"),
			);
			await expectMatch(client, await read(client, client.token, device("198.51.100.7", "browser-a")));
			const otherBrowser = await read(
				client,
				client.token,
				device("198.51.100.7", "browser-b", "Windows"),
			);
			if (mode === "strict") {
				await expectSignedOut(otherBrowser);
			} else {
				await expectRebind(client, otherBrowser, client.token);
			}
		}
	});

	test("tokens issued by direct server calls are bound to the server's request context", async () => {
		const auth = createAuth({ placement: "header" });
		const { headers } = await auth.api.signUpEmail({
			body: { name: "Server Issued", email: "server-issued@example.com", password: PASSWORD },
			headers: new Headers({ "user-agent": "backend-service" }),
			returnHeaders: true,
		});
		const token = headers.get("set-auth-token") ?? "";
		await expectSignedOut(
			await requestSession(
				auth,
				new Headers({ "user-agent": "browser", authorization: `Bearer ${token}` }),
			),
		);
		const server = await requestSession(
			auth,
			new Headers({ "user-agent": "backend-service", authorization: `Bearer ${token}` }),
		);
		expect(await server.json()).toMatchObject({ user: { email: "server-issued@example.com" } });
	});
});

describe("dynamic fingerprint mode", () => {
	test("tolerates one changed signal at a time and re-binds the token to it", async () => {
		for (const placement of PLACEMENTS) {
			const client = await signUp(
				createAuth({ placement, fingerprint: { mode: "dynamic" } }),
				placement,
				`${placement}-dynamic@example.com`,
				device("203.0.113.10"),
			);
			await expectMatch(client, await read(client, client.token, device("203.0.113.77")));

			const mobile = await expectRebind(
				client,
				await read(client, client.token, device("198.51.100.20")),
				client.token,
			);
			// The original binding is unchanged for the original device.
			await expectMatch(client, await read(client, client.token, device("203.0.113.10")));
			// Relative to the re-bound token only the User-Agent changes now.
			const updated = await expectRebind(
				client,
				await read(client, mobile, device("198.51.100.20", "agent-b")),
				mobile,
			);
			await expectMatch(client, await read(client, updated, device("198.51.100.20", "agent-b")));

			// Relative to the original token both the network and the User-Agent changed.
			await expectSignedOut(
				await read(client, client.token, device("198.51.100.20", "agent-b")),
			);
			await expectSignedOut(
				await read(client, client.token, device("203.0.113.10", "agent-a", "Windows")),
			);
		}
	});

	test("compares IPv6 clients by their /48 network", async () => {
		const client = await signUp(
			createAuth({ fingerprint: { mode: "dynamic" } }),
			"cookie",
			"dynamic-ipv6@example.com",
			device("2001:db8:1:2::1"),
		);
		await expectMatch(client, await read(client, client.token, device("2001:db8:1:ff::1")));
		await expectRebind(client, await read(client, client.token, device("2001:db8:2::1")), client.token);
	});

	test("never re-binds responses that end, fail, or replace the session", async () => {
		for (const placement of PLACEMENTS) {
			const db = createMemoryDB();
			const auth = createAuth({ placement, db, fingerprint: { mode: "dynamic" } });
			const client = await signUp(
				auth,
				placement,
				`${placement}-rebind-guards@example.com`,
				device("203.0.113.10"),
			);
			const drifted = device("198.51.100.20");
			const post = (path: string, body: object) => {
				const headers = present(placement, client.cookieName, client.token, drifted);
				headers.set("content-type", "application/json");
				headers.set("origin", TEST_BASE_URL);
				return auth.handler(
					new Request(`${TEST_BASE_URL}/api/auth${path}`, {
						method: "POST",
						headers,
						body: JSON.stringify(body),
					}),
				);
			};

			const failed = await post("/change-password", {
				currentPassword: "not-the-password",
				newPassword: `${PASSWORD}-new`,
			});
			expect(failed.status).toBe(400);
			expect(deliveredToken(failed, placement, client.cookieName)).toBeNull();

			const revoked = await post("/revoke-session", { token: rowAt(db.session).token });
			expect(revoked.status).toBe(200);
			expect(db.session).toHaveLength(0);
			expect(deliveredToken(revoked, placement, client.cookieName)).toBeNull();
		}
	});

	test("sign-out from a drifted device ends the session and issues nothing", async () => {
		for (const placement of PLACEMENTS) {
			const db = createMemoryDB();
			const auth = createAuth({ placement, db, fingerprint: { mode: "dynamic" } });
			const client = await signUp(
				auth,
				placement,
				`${placement}-drifted-sign-out@example.com`,
				device("203.0.113.10"),
			);
			const headers = present(placement, client.cookieName, client.token, device("198.51.100.20"));
			headers.set("origin", TEST_BASE_URL);
			const response = await auth.handler(
				new Request(`${TEST_BASE_URL}/api/auth/sign-out`, { method: "POST", headers }),
			);
			expect(response.status).toBe(200);
			expect(db.session).toHaveLength(0);
			expect(deliveredToken(response, placement, client.cookieName)).toBeNull();
		}
	});

	test("a response that clears the session cookie is not re-bound", async () => {
		const db = createMemoryDB();
		const auth = createAuth({ db, fingerprint: { mode: "dynamic" }, plugins: [clearCookieFixture] });
		const client = await signUp(auth, "cookie", "cleared-cookie@example.com", device("203.0.113.10"));
		const headers = present("cookie", client.cookieName, client.token, device("198.51.100.20"));
		headers.set("origin", TEST_BASE_URL);
		const response = await auth.handler(
			new Request(`${TEST_BASE_URL}/api/auth/clear-session-cookie`, { method: "POST", headers }),
		);
		expect(response.status).toBe(200);
		expect(db.session).toHaveLength(1);
		const cookie = parseSetCookieHeader(response.headers.get("set-cookie") ?? "").get(
			client.cookieName,
		);
		expect({ value: cookie?.value, maxAge: cookie?.["max-age"] }).toEqual({ value: "", maxAge: 0 });
	});

	test("re-bound rememberMe: false tokens keep the non-persistent policy", async () => {
		for (const placement of PLACEMENTS) {
			const auth = createAuth({ placement, fingerprint: { mode: "dynamic" } });
			const email = `${placement}-dynamic-nonpersistent@example.com`;
			await signUp(auth, placement, email, device("203.0.113.10"));
			const signIn = await auth.handler(
				new Request(`${TEST_BASE_URL}/api/auth/sign-in/email`, {
					method: "POST",
					headers: { ...device("203.0.113.10"), "content-type": "application/json" },
					body: JSON.stringify({ email, password: PASSWORD, rememberMe: false }),
				}),
			);
			const cookieName = (await auth.$context).authCookies.sessionToken.name;
			const token = deliveredToken(signIn, placement, cookieName) ?? "";
			expect(decodeJwt(token).remember).toBe(false);
			const client: Client = { auth, placement, cookieName, email, token };

			const response = await read(client, token, device("198.51.100.20"));
			const setCookie = response.headers.get("set-cookie") ?? "";
			const replacement = await expectRebind(client, response, token);
			expect(decodeJwt(replacement).remember).toBe(false);
			if (placement === "cookie") {
				expect(parseSetCookieHeader(setCookie).get(cookieName)?.["max-age"]).toBeUndefined();
			}
		}
	});
});

describe("loose fingerprint mode", () => {
	test("re-binds a token whose IP, User-Agent, and platform all changed", async () => {
		for (const placement of PLACEMENTS) {
			const client = await signUp(
				createAuth({ placement, fingerprint: { mode: "loose" } }),
				placement,
				`${placement}-loose@example.com`,
				device("203.0.113.10"),
			);
			const elsewhere = device("198.51.100.20", "agent-b", "Windows");
			const replacement = await expectRebind(
				client,
				await read(client, client.token, elsewhere),
				client.token,
			);
			await expectMatch(client, await read(client, replacement, elsewhere));
		}
	});
});
