import { describe, expect, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { parseSetCookieHeader } from "better-auth/cookies";
import { scjwt } from "../src/plugin/index";
import {
	deliverSessionToken,
	hasLiveSetCookie,
} from "../src/plugin/token-deliver";
import { TEST_BASE_URL, TEST_SECRET, createMemoryDB } from "./helpers/native-auth";

const TOKEN = "header.payload.signature";
const PAST = "Thu, 01 Jan 1970 00:00:00 GMT";
const FUTURE = new Date(Date.now() + 24 * 60 * 60 * 1000).toUTCString();

async function authCookies() {
	const auth = betterAuth({
		database: memoryAdapter(createMemoryDB()),
		baseURL: TEST_BASE_URL,
		secret: TEST_SECRET,
		plugins: [scjwt()],
	});
	return (await auth.$context).authCookies;
}

function deliver(
	setCookies: string[],
	placement: "cookie" | "header",
	cookies: Awaited<ReturnType<typeof authCookies>>,
): string[] {
	const headers = new Headers();
	for (const value of setCookies) headers.append("set-cookie", value);
	deliverSessionToken(headers, TOKEN, placement, cookies);
	return headers.getSetCookie();
}

/** Lifetime attribute combinations and whether each keeps the cookie alive. */
const LIFETIMES: Array<[attributes: string, live: boolean]> = [
	["Max-Age=-1", false],
	["Max-Age=0", false],
	[`Max-Age=60; Expires=${PAST}`, true],
	[`Max-Age=-1; Expires=${FUTURE}`, false],
	[`Expires=${FUTURE}`, true],
	[`Expires=${PAST}`, false],
	["", true],
];

describe("session token delivery honors cookie lifetime precedence", () => {
	for (const [attributes, live] of LIFETIMES) {
		const suffix = attributes ? `; ${attributes}` : "";
		const label = attributes || "no lifetime attributes";

		test(`header placement ${live ? "removes" : "preserves"} a session cookie with ${label}`, async () => {
			const cookies = await authCookies();
			const native = `${cookies.sessionToken.name}=native; Path=/${suffix}`;
			const result = deliver([native], "header", cookies);
			expect(result.includes(native)).toBe(!live);
		});

		test(`cookie placement ${live ? "replaces" : "keeps"} a session cookie with ${label}`, async () => {
			const cookies = await authCookies();
			const native = `${cookies.sessionToken.name}=native; Path=/; HttpOnly${suffix}`;
			const [result] = deliver([native], "cookie", cookies);
			const parsed = parseSetCookieHeader(result ?? "").get(cookies.sessionToken.name);
			expect(parsed?.value).toBe(live ? TOKEN : "native");
			expect(parsed?.httponly).toBe(true);
			expect(parsed?.path).toBe("/");
		});

		test(`hasLiveSetCookie reports ${live} for ${label}`, async () => {
			const cookies = await authCookies();
			const headers = new Headers({
				"set-cookie": `${cookies.dontRememberToken.name}=marker${suffix}`,
			});
			expect(hasLiveSetCookie(headers, cookies.dontRememberToken.name)).toBe(live);
		});
	}

	test("empty values are always clearing instructions", async () => {
		const cookies = await authCookies();
		const clearing = `${cookies.sessionToken.name}=; Max-Age=60`;
		expect(deliver([clearing], "header", cookies)).toEqual([clearing]);
		expect(deliver([clearing], "cookie", cookies)).toEqual([clearing]);
	});

	test("the last Set-Cookie for a name decides liveness", async () => {
		const name = (await authCookies()).dontRememberToken.name;
		const headers = new Headers();
		headers.append("set-cookie", `${name}=marker`);
		headers.append("set-cookie", `${name}=; Max-Age=0`);
		expect(hasLiveSetCookie(headers, name)).toBe(false);
		headers.append("set-cookie", `${name}=marker; Max-Age=60`);
		expect(hasLiveSetCookie(headers, name)).toBe(true);
		expect(hasLiveSetCookie(undefined, name)).toBe(false);
		expect(hasLiveSetCookie(new Headers(), name)).toBe(false);
	});

	test("unrelated and account cookies are preserved in both placements", async () => {
		const cookies = await authCookies();
		const unrelated = `app_pref=dark; Path=/; Max-Age=600`;
		const account = `${cookies.accountData.name}=account; Path=/; Max-Age=600`;
		for (const placement of ["cookie", "header"] as const) {
			const result = deliver([unrelated, account], placement, cookies);
			expect(result).toEqual([unrelated, account]);
		}
	});
});

describe("session token delivery transport details", () => {
	test("cookie placement keeps every native attribute on the substituted SCJWT", async () => {
		const cookies = await authCookies();
		const native = `${cookies.sessionToken.name}=native; Path=/app; Domain=example.com; Max-Age=600; HttpOnly; Secure; SameSite=None; Partitioned`;
		const [result] = deliver([native], "cookie", cookies);
		const parsed = parseSetCookieHeader(result ?? "").get(cookies.sessionToken.name);
		expect(parsed).toMatchObject({
			value: TOKEN,
			path: "/app",
			domain: "example.com",
			"max-age": 600,
			httponly: true,
			secure: true,
			samesite: "none",
			partitioned: true,
		});
	});

	test("header placement removes live session-data chunks and markers but keeps clearing chunks", async () => {
		const cookies = await authCookies();
		const data = cookies.sessionData.name;
		const kept = [`${data}.1=; Max-Age=0`, "app_pref=dark"];
		const result = deliver(
			[
				`${cookies.sessionToken.name}=native; Max-Age=600`,
				`${data}.0=chunk-zero; Max-Age=300`,
				...kept,
				`${cookies.dontRememberToken.name}=true.signature`,
			],
			"header",
			cookies,
		);
		expect(result).toEqual(kept);
	});

	test("falls back to splitting a combined Set-Cookie header", async () => {
		const cookies = await authCookies();
		const headers = new Headers();
		headers.append(
			"set-cookie",
			`${cookies.sessionToken.name}=native; Expires=${FUTURE}; Path=/`,
		);
		headers.append("set-cookie", `app_pref=dark; Expires=${FUTURE}`);
		// Runtimes without Headers#getSetCookie only expose the comma-joined value.
		Object.defineProperty(headers, "getSetCookie", { value: undefined });
		deliverSessionToken(headers, TOKEN, "cookie", cookies);
		const delivered = parseSetCookieHeader(headers.get("set-cookie") ?? "");
		expect(delivered.get(cookies.sessionToken.name)?.value).toBe(TOKEN);
		expect(delivered.get("app_pref")?.value).toBe("dark");
	});

	test("header placement exposes set-auth-token once and keeps other exposed headers", async () => {
		const cookies = await authCookies();
		const headers = new Headers({
			"access-control-expose-headers": "X-Request-Id, Set-Auth-Token,  ",
			"x-request-id": "abc",
		});
		deliverSessionToken(headers, TOKEN, "header", cookies);
		deliverSessionToken(headers, TOKEN, "header", cookies);
		const exposed = (headers.get("access-control-expose-headers") ?? "")
			.split(",")
			.map((name) => name.trim().toLowerCase());
		expect(exposed.filter((name) => name === "set-auth-token")).toHaveLength(1);
		expect(exposed).toContain("x-request-id");
		expect(headers.get("x-request-id")).toBe("abc");
		expect(headers.get("set-auth-token")).toBe(TOKEN);
	});
});
