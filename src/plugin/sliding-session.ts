import type { AuthContext } from "better-auth";
import { SLIDING_THRESHOLD_RATIO } from "./constants";
import { signJwtFromParts } from "./jwt";
import type { ResolvedScjwtOptions, ScjwtJwtPayload } from "./types";

export interface RefreshSlidingSessionParams {
	adapter: AuthContext["adapter"];
	options: ResolvedScjwtOptions;
	payload: ScjwtJwtPayload;
	userId: string;
	fingerprint: string;
	nowSeconds?: number;
}

/**
 * Seconds before JWT expiry at which sliding refresh should run (20% of TTL).
 */
export function getSlidingRefreshThreshold(expiresInSeconds: number): number {
	return Math.floor(expiresInSeconds * SLIDING_THRESHOLD_RATIO);
}

/**
 * Returns true when the JWT is within the sliding refresh window.
 */
export function shouldRefreshSlidingSession(
	payload: ScjwtJwtPayload,
	expiresInSeconds: number,
	nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
	const remainingLifetime = payload.exp - nowSeconds;
	const threshold = getSlidingRefreshThreshold(expiresInSeconds);
	return remainingLifetime <= threshold;
}

/**
 * Extends the backing session and re-signs the JWT when sliding refresh applies.
 * Returns `null` when refresh is disabled or not yet due.
 */
export async function refreshSlidingSession(
	params: RefreshSlidingSessionParams,
): Promise<string | null> {
	if (!params.options.slidingSession) {
		return null;
	}

	const nowSeconds = params.nowSeconds ?? Math.floor(Date.now() / 1000);

	if (
		!shouldRefreshSlidingSession(
			params.payload,
			params.options.expiresInSeconds,
			nowSeconds,
		)
	) {
		return null;
	}

	const newExpiresAt = new Date(
		(nowSeconds + params.options.expiresInSeconds) * 1000,
	);

	await params.adapter.update({
		model: "session",
		where: [{ field: "id", value: params.payload.sid }],
		update: { expiresAt: newExpiresAt },
	});

	return signJwtFromParts({
		jwtSecret: params.options.jwtSecret,
		issuer: params.options.issuer,
		userId: params.userId,
		fingerprint: params.fingerprint,
		sessionId: params.payload.sid,
		expiresInSeconds: params.options.expiresInSeconds,
		issuedAt: nowSeconds,
	});
}
