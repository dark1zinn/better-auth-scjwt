import type { Session } from "better-auth";

/**
 * Converts a Better Auth session `expiresAt` value to Unix epoch seconds.
 */
export function sessionExpiresAtToSeconds(
	expiresAt: Session["expiresAt"],
): number {
	const expiresAtMs =
		expiresAt instanceof Date
			? expiresAt.getTime()
			: new Date(expiresAt).getTime();

	if (Number.isNaN(expiresAtMs)) {
		return 0;
	}

	return Math.floor(expiresAtMs / 1000);
}

/**
 * Effective session expiry: the earlier of JWT `exp` and database `expiresAt`.
 */
export function getEffectiveExpirySeconds(
	jwtExp: number,
	sessionExpiresAt: Session["expiresAt"],
): number {
	const dbExp = sessionExpiresAtToSeconds(sessionExpiresAt);
	return Math.min(jwtExp, dbExp);
}

/**
 * Returns true when the current time is at or past the effective expiry.
 */
export function isPastEffectiveExpiry(
	jwtExp: number,
	sessionExpiresAt: Session["expiresAt"],
	nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
	return nowSeconds >= getEffectiveExpirySeconds(jwtExp, sessionExpiresAt);
}

/**
 * JWT TTL capped by remaining database session lifetime at issuance.
 * Returns `0` when the session is already expired.
 */
export function computeJwtExpiresInSeconds(
	issuedAt: number,
	configuredTtl: number,
	sessionExpiresAt: Session["expiresAt"],
): number {
	const dbExp = sessionExpiresAtToSeconds(sessionExpiresAt);
	const sessionRemaining = dbExp - issuedAt;
	return Math.min(configuredTtl, Math.max(0, sessionRemaining));
}
