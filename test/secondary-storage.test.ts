import { describe, expect, setSystemTime, test } from "bun:test";
import type { SecondaryStorage } from "@better-auth/core/db";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { parseSetCookieHeader } from "better-auth/cookies";
import { scjwt } from "../src/plugin/index";
import {
	TEST_BASE_URL,
	TEST_SECRET,
	createCookieHeaders,
	createMemoryDB,
	requestSession,
	rowAt,
	signUpWithScjwt,
} from "./helpers/native-auth";

/** In-memory secondary storage plus its backing map, so tests can evict entries. */
function createSecondaryStorage(): {
	storage: SecondaryStorage;
	values: Map<string, string>;
} {
	const values = new Map<string, string>();
	const storage: SecondaryStorage = {
		get(key) {
			return values.get(key) ?? null;
		},
		getAndDelete(key) {
			const value = values.get(key) ?? null;
			values.delete(key);
			return value;
		},
		increment(key) {
			const value = Number(values.get(key) ?? "0") + 1;
			values.set(key, String(value));
			return value;
		},
		set(key, value) {
			values.set(key, value);
		},
		delete(key) {
			values.delete(key);
		},
	};
	return { storage, values };
}

describe("database-backed session invariant", () => {
	test("rejects SCJWT without a Better Auth database", async () => {
		const auth = betterAuth({
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			plugins: [scjwt()],
		});
		await expect(auth.$context).rejects.toThrow(
			"a Better Auth database is required",
		);
	});

	test("rejects secondary-storage-only sessions", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			secondaryStorage: createSecondaryStorage().storage,
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			plugins: [scjwt()],
		});
		await expect(auth.$context).rejects.toThrow(
			"secondaryStorage requires session.storeSessionInDatabase: true",
		);
	});

	test("accepts secondary storage when sessions remain database-backed", async () => {
		const auth = betterAuth({
			database: memoryAdapter(createMemoryDB()),
			secondaryStorage: createSecondaryStorage().storage,
			session: { storeSessionInDatabase: true },
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			plugins: [scjwt()],
		});
		await expect(auth.$context).resolves.toMatchObject({
			baseURL: `${TEST_BASE_URL}/api/auth`,
		});
	});

	test("rejects a preserved database row once secondary storage drops the session", async () => {
		const db = createMemoryDB();
		const { storage, values } = createSecondaryStorage();
		const auth = betterAuth({
			database: memoryAdapter(db),
			secondaryStorage: storage,
			session: {
				storeSessionInDatabase: true,
				preserveSessionInDatabase: true,
			},
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "preserved-row@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		expect((await requestSession(auth, headers)).status).toBe(200);

		const row = rowAt(db.session);
		expect(values.has(row.token)).toBe(true);
		values.delete(row.token);
		expect(db.session).toHaveLength(1);
		expect(new Date(row.expiresAt).getTime()).toBeGreaterThan(Date.now());

		const response = await requestSession(auth, headers);
		expect(response.status).toBe(401);
	});
});

describe("authoritative storage failures", () => {
	/**
	 * A memory adapter whose session reads can be failed and whose session
	 * updates can be paused, to drive storage outages and races deterministically.
	 */
	function controllableAdapter(db: ReturnType<typeof createMemoryDB>) {
		const control: {
			failSessionReads: boolean;
			pauseSessionUpdate: { reached: () => void; release: Promise<void> } | null;
		} = { failSessionReads: false, pauseSessionUpdate: null };
		const base = memoryAdapter(db);
		const adapter: typeof base = (options) => {
			const instance = base(options);
			return {
				...instance,
				async findOne(args) {
					if (control.failSessionReads && args.model === "session") {
						throw new Error("session database unavailable");
					}
					return instance.findOne(args);
				},
				async update(args) {
					const pause = control.pauseSessionUpdate;
					if (pause && args.model === "session") {
						control.pauseSessionUpdate = null;
						pause.reached();
						await pause.release;
					}
					return instance.update(args);
				},
			};
		};
		return { adapter, control };
	}

	async function expectNoCredential(response: Response, cookieName: string) {
		expect(response.headers.get("set-auth-token")).toBeNull();
		const token = parseSetCookieHeader(response.headers.get("set-cookie") ?? "").get(
			cookieName,
		)?.value;
		expect(token ?? "").toBe("");
	}

	test("fails closed when the session row cannot be read, then recovers", async () => {
		const db = createMemoryDB();
		const { adapter, control } = controllableAdapter(db);
		const auth = betterAuth({
			database: adapter,
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "db-outage@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		control.failSessionReads = true;
		const outage = await requestSession(auth, headers);
		// An outage is a server error, not a bad credential, and authenticates nobody.
		expect(outage.status).toBe(500);
		await expectNoCredential(outage, issued.cookieName);
		control.failSessionReads = false;
		expect((await requestSession(auth, headers)).status).toBe(200);
		expect(db.session).toHaveLength(1);
	});

	test("fails closed when secondary storage cannot be read, without falling back to the row", async () => {
		const db = createMemoryDB();
		const { storage } = createSecondaryStorage();
		let failStorage = false;
		const auth = betterAuth({
			database: memoryAdapter(db),
			secondaryStorage: {
				...storage,
				get(key) {
					if (failStorage) throw new Error("secondary storage unavailable");
					return storage.get(key);
				},
			},
			session: { storeSessionInDatabase: true },
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt()],
		});
		const issued = await signUpWithScjwt(auth, "storage-outage@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		failStorage = true;
		const outage = await requestSession(auth, headers);
		expect(outage.status).toBe(500);
		await expectNoCredential(outage, issued.cookieName);
		failStorage = false;
		expect((await requestSession(auth, headers)).status).toBe(200);
	});

	test("rejects a token whose row resolves to a different live session", async () => {
		const db = createMemoryDB();
		const { storage, values } = createSecondaryStorage();
		const auth = betterAuth({
			database: memoryAdapter(db),
			secondaryStorage: storage,
			session: { storeSessionInDatabase: true },
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			plugins: [scjwt()],
		});
		const victim = await signUpWithScjwt(auth, "mismatch-victim@example.com");
		await signUpWithScjwt(auth, "mismatch-other@example.com");
		const victimRow = rowAt(db.session, 0);
		const otherRow = rowAt(db.session, 1);
		const original = values.get(victimRow.token);
		values.set(victimRow.token, values.get(otherRow.token) ?? "");
		const headers = createCookieHeaders(victim.cookieName, victim.token);
		expect((await requestSession(auth, headers)).status).toBe(401);
		values.set(victimRow.token, original ?? "");
		expect((await requestSession(auth, headers)).status).toBe(200);
	});

	test("a refresh racing a completed revocation leaves no usable token", async () => {
		const db = createMemoryDB();
		const { adapter, control } = controllableAdapter(db);
		const auth = betterAuth({
			database: adapter,
			baseURL: TEST_BASE_URL,
			secret: TEST_SECRET,
			emailAndPassword: { enabled: true },
			session: { expiresIn: 3600, updateAge: 0 },
			plugins: [scjwt()],
		});
		const context = await auth.$context;
		const issued = await signUpWithScjwt(auth, "refresh-race@example.com");
		const headers = createCookieHeaders(issued.cookieName, issued.token);
		const atUpdate = Promise.withResolvers<void>();
		const release = Promise.withResolvers<void>();
		control.pauseSessionUpdate = { reached: atUpdate.resolve, release: release.promise };
		setSystemTime(new Date(Date.now() + 2000));
		try {
			// The refresh has authenticated and is about to extend the row.
			const inflight = requestSession(auth, headers);
			await atUpdate.promise;
			await context.internalAdapter.deleteSession(rowAt(db.session).token ?? "");
			expect(db.session).toHaveLength(0);
			release.resolve();
			const raced = await inflight;
			// Better Auth's refresh finds the row gone and refuses the request.
			expect(raced.status).toBe(401);
			const replacement = parseSetCookieHeader(raced.headers.get("set-cookie") ?? "").get(
				issued.cookieName,
			)?.value;
			for (const token of [issued.token, replacement].filter(
				(value): value is string => Boolean(value),
			)) {
				const response = await requestSession(
					auth,
					createCookieHeaders(issued.cookieName, token),
				);
				expect(response.status).toBe(401);
			}
		} finally {
			setSystemTime();
		}
	});
});
