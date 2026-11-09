import { describe, expect, setSystemTime, test } from "bun:test";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { parseSetCookieHeader } from "better-auth/cookies";
import { decodeJwt } from "jose";
import { scjwt } from "../src/plugin/index";
import {
	STABLE_HEADERS,
	TEST_BASE_URL,
	TEST_SECRET,
	createMemoryDB,
	requestSession,
	rowAt,
	type TestDB,
} from "./helpers/native-auth";

const PASSWORD = "correct-horse-battery-staple";
const STRATEGIES = ["compact", "jwt", "jwe"] as const;

function createAuth(
	db: TestDB,
	options: {
		strategy?: (typeof STRATEGIES)[number];
		tokenPlacement?: "cookie" | "header";
		updateAge?: number;
	} = {},
) {
	return betterAuth({
		database: memoryAdapter(db),
		baseURL: TEST_BASE_URL,
		secret: TEST_SECRET,
		emailAndPassword: { enabled: true },
		user: { additionalFields: { bio: { type: "string", required: false } } },
		session: {
			expiresIn: 3600,
			updateAge: options.updateAge,
			cookieCache: { enabled: true, maxAge: 300, strategy: options.strategy },
			additionalFields: { deviceLabel: { type: "string", required: false } },
		},
		plugins: [scjwt({ tokenPlacement: options.tokenPlacement })],
	});
}

type Auth = ReturnType<typeof createAuth>;

interface SessionBody {
	session: { id: string; deviceLabel?: string | null };
	user: { id: string; name: string; bio?: string | null };
}

async function signUp(
	auth: Auth,
	email: string,
	extra: Record<string, unknown> = {},
): Promise<{ response: Response; cookies: Map<string, string> }> {
	const response = await auth.handler(
		new Request(`${TEST_BASE_URL}/api/auth/sign-up/email`, {
			method: "POST",
			headers: { ...STABLE_HEADERS, "content-type": "application/json" },
			body: JSON.stringify({ name: "Cached User", email, password: PASSWORD, ...extra }),
		}),
	);
	expect(response.status).toBe(200);
	const cookies = new Map<string, string>();
	for (const [name, attributes] of parseSetCookieHeader(
		response.headers.get("set-cookie") ?? "",
	)) {
		if (attributes.value) cookies.set(name, attributes.value);
	}
	return { response, cookies };
}

/** A browser replaying every cookie it holds. */
function browserHeaders(cookies: Map<string, string>): Headers {
	const headers = new Headers(STABLE_HEADERS);
	headers.set(
		"cookie",
		[...cookies].map(([name, value]) => `${name}=${encodeURIComponent(value)}`).join("; "),
	);
	return headers;
}

async function readSession(auth: Auth, headers: Headers): Promise<SessionBody> {
	const response = await requestSession(auth, headers);
	expect(response.status).toBe(200);
	return (await response.json()) as SessionBody;
}

describe("cookie cache under SCJWT", () => {
	for (const strategy of STRATEGIES) {
		test(`${strategy} snapshots never override current session and user data`, async () => {
			const db = createMemoryDB();
			const auth = createAuth(db, { strategy });
			const context = await auth.$context;
			const { cookies } = await signUp(auth, `${strategy}-cache@example.com`);
			expect(cookies.has(context.authCookies.sessionData.name)).toBe(true);
			const userId = rowAt(db.user).id;
			await context.internalAdapter.updateUser(userId, { name: "Renamed" });
			await context.internalAdapter.updateSession(rowAt(db.session).token, {
				deviceLabel: "rotated",
			});
			const body = await readSession(auth, browserHeaders(cookies));
			expect(body.user.name).toBe("Renamed");
			expect(body.session.deviceLabel).toBe("rotated");
		});
	}

	test("chunked snapshots are ignored as a whole", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db);
		const context = await auth.$context;
		const { cookies } = await signUp(auth, "chunked-cache@example.com", {
			bio: "b".repeat(6000),
		});
		const chunkNames = [...cookies.keys()].filter((name) =>
			name.startsWith(`${context.authCookies.sessionData.name}.`),
		);
		expect(chunkNames.length).toBeGreaterThan(1);
		await context.internalAdapter.updateUser(rowAt(db.user).id, { bio: "short" });
		expect((await readSession(auth, browserHeaders(cookies))).user.bio).toBe("short");
	});

	test("a revoked session stays rejected while its snapshot is still fresh", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db);
		const { cookies } = await signUp(auth, "revoked-cache@example.com");
		await (await auth.$context).internalAdapter.deleteSession(rowAt(db.session).token);
		const response = await requestSession(auth, browserHeaders(cookies));
		expect(response.status).toBe(401);
	});

	test("another user's snapshot cannot change who the SCJWT authenticates", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db);
		const context = await auth.$context;
		const victim = await signUp(auth, "cache-owner@example.com");
		const other = await signUp(auth, "cache-other@example.com");
		const mixed = new Map(victim.cookies);
		for (const [name, value] of other.cookies) {
			if (name.startsWith(context.authCookies.sessionData.name)) mixed.set(name, value);
		}
		const body = await readSession(auth, browserHeaders(mixed));
		expect(body.user.id).toBe(rowAt(db.user).id);
	});

	test("header placement never authenticates from native cache cookies alone", async () => {
		const auth = createAuth(createMemoryDB(), { tokenPlacement: "header" });
		const cookieAuth = createAuth(createMemoryDB());
		const { cookies } = await signUp(cookieAuth, "header-cache@example.com");
		const response = await requestSession(auth, browserHeaders(cookies));
		expect(response.status).toBe(200);
		expect(await response.json()).toBeNull();
	});

	test("refresh and the non-persistent policy still apply with a cache present", async () => {
		const db = createMemoryDB();
		const auth = createAuth(db, { updateAge: 0 });
		const sessionCookieName = (await auth.$context).authCookies.sessionToken.name;
		const remembered = await signUp(auth, "cache-refresh@example.com");
		const nonpersistent = await signUp(auth, "cache-nonpersistent@example.com", {
			rememberMe: false,
		});
		setSystemTime(new Date(Date.now() + 2000));
		try {
			const refreshed = await requestSession(auth, browserHeaders(remembered.cookies));
			const replacement = parseSetCookieHeader(
				refreshed.headers.get("set-cookie") ?? "",
			).get(sessionCookieName)?.value;
			expect(decodeJwt(replacement ?? "").sid).toBe(rowAt(db.session).id);

			const before = new Date(rowAt(db.session, 1).expiresAt).getTime();
			const unchanged = await requestSession(auth, browserHeaders(nonpersistent.cookies));
			expect(unchanged.status).toBe(200);
			expect(
				parseSetCookieHeader(unchanged.headers.get("set-cookie") ?? "").get(
					sessionCookieName,
				),
			).toBeUndefined();
			expect(new Date(rowAt(db.session, 1).expiresAt).getTime()).toBe(before);
		} finally {
			setSystemTime();
		}
	});
});
