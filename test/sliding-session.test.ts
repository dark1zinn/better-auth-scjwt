import { describe, expect, test } from "bun:test";
import { SLIDING_THRESHOLD_RATIO } from "../src/plugin/constants";
import {
	getSlidingRefreshThreshold,
	refreshSlidingSession,
	shouldRefreshSlidingSession,
} from "../src/plugin/sliding-session";
import { verifyJwt } from "../src/plugin/jwt";
import type { ResolvedScjwtOptions, ScjwtJwtPayload } from "../src/plugin/types";
import {
	TEST_FINGERPRINT,
	TEST_ISSUER,
	TEST_JWT_SECRET,
	TEST_SESSION_ID,
	TEST_USER_ID,
} from "./helpers/fixtures";
import { createMockAdapter } from "./helpers/mock-adapter";

const EXPIRES_IN_SECONDS = 3600;

const slidingOptions: ResolvedScjwtOptions = {
	jwtSecret: TEST_JWT_SECRET,
	issuer: TEST_ISSUER,
	expiresInSeconds: EXPIRES_IN_SECONDS,
	cookieName: "auth-token",
	tokenPlacement: "cookie",
	slidingSession: true,
};

const disabledOptions: ResolvedScjwtOptions = {
	...slidingOptions,
	slidingSession: false,
};

function createPayload(exp: number, iat = exp - EXPIRES_IN_SECONDS): ScjwtJwtPayload {
	return {
		iss: TEST_ISSUER,
		sub: `user:${TEST_USER_ID}`,
		fp: TEST_FINGERPRINT,
		iat,
		exp,
		sid: TEST_SESSION_ID,
	};
}

describe("getSlidingRefreshThreshold", () => {
	test("uses 20% of the configured token lifetime", () => {
		expect(getSlidingRefreshThreshold(3600)).toBe(
			Math.floor(3600 * SLIDING_THRESHOLD_RATIO),
		);
		expect(getSlidingRefreshThreshold(100)).toBe(20);
	});
});

describe("shouldRefreshSlidingSession", () => {
	const threshold = getSlidingRefreshThreshold(EXPIRES_IN_SECONDS);
	const nowSeconds = Math.floor(Date.now() / 1000);
	const exp = nowSeconds + threshold + 100;
	const refreshAt = exp - threshold;

	test("returns false above the threshold window", () => {
		expect(
			shouldRefreshSlidingSession(
				createPayload(exp),
				EXPIRES_IN_SECONDS,
				refreshAt - 1,
			),
		).toBe(false);
	});

	test("returns true at the threshold boundary", () => {
		expect(
			shouldRefreshSlidingSession(
				createPayload(exp),
				EXPIRES_IN_SECONDS,
				refreshAt,
			),
		).toBe(true);
	});

	test("returns true below the threshold window", () => {
		expect(
			shouldRefreshSlidingSession(
				createPayload(exp),
				EXPIRES_IN_SECONDS,
				refreshAt + 1,
			),
		).toBe(true);
	});
});

describe("refreshSlidingSession", () => {
	const threshold = getSlidingRefreshThreshold(EXPIRES_IN_SECONDS);
	const baseNow = Math.floor(Date.now() / 1000);
	const exp = baseNow + threshold + 100;
	const nowSeconds = baseNow + 100;
	const payload = createPayload(exp, nowSeconds - EXPIRES_IN_SECONDS);

	test("returns null when slidingSession is disabled", async () => {
		const { adapter, updates } = createMockAdapter();

		const result = await refreshSlidingSession({
			adapter,
			options: disabledOptions,
			payload,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			nowSeconds,
		});

		expect(result).toBeNull();
		expect(updates).toHaveLength(0);
	});

	test("returns null when refresh is not yet due", async () => {
		const { adapter, updates } = createMockAdapter();
		const tooEarly = nowSeconds - 1;

		const result = await refreshSlidingSession({
			adapter,
			options: slidingOptions,
			payload,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			nowSeconds: tooEarly,
		});

		expect(result).toBeNull();
		expect(updates).toHaveLength(0);
	});

	test("extends the session and re-signs the JWT when due", async () => {
		const { adapter, updates } = createMockAdapter();

		const token = await refreshSlidingSession({
			adapter,
			options: slidingOptions,
			payload,
			userId: TEST_USER_ID,
			fingerprint: TEST_FINGERPRINT,
			nowSeconds,
		});

		expect(token).toBeString();
		expect(updates).toHaveLength(1);
		expect(updates[0]).toEqual({
			model: "session",
			where: [{ field: "id", value: TEST_SESSION_ID }],
			update: {
				expiresAt: new Date((nowSeconds + EXPIRES_IN_SECONDS) * 1000),
			},
		});

		const verified = await verifyJwt({
			token: token!,
			jwtSecret: TEST_JWT_SECRET,
			issuer: TEST_ISSUER,
		});

		expect(verified).toMatchObject({
			iss: TEST_ISSUER,
			sub: `user:${TEST_USER_ID}`,
			fp: TEST_FINGERPRINT,
			sid: TEST_SESSION_ID,
			iat: nowSeconds,
			exp: nowSeconds + EXPIRES_IN_SECONDS,
		});
	});
});
