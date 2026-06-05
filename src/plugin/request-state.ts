import type { PendingRefresh } from "./types";

const PENDING_REFRESH_KEY = "scjwtPendingRefresh";

export function setPendingRefresh(
	context: Record<string, unknown>,
	refresh: PendingRefresh,
): void {
	context[PENDING_REFRESH_KEY] = refresh;
}

export function getPendingRefresh(
	context: Record<string, unknown>,
): PendingRefresh | undefined {
	return context[PENDING_REFRESH_KEY] as PendingRefresh | undefined;
}

export function clearPendingRefresh(context: Record<string, unknown>): void {
	delete context[PENDING_REFRESH_KEY];
}

/**
 * Returns a pending refresh and removes it from the auth context.
 */
export function takePendingRefresh(
	context: Record<string, unknown>,
): PendingRefresh | undefined {
	const refresh = getPendingRefresh(context);
	if (refresh) {
		clearPendingRefresh(context);
	}
	return refresh;
}
