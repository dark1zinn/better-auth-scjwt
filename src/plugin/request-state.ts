import type { PendingRefresh } from "./types";

const pendingRefreshes = new WeakMap<Request, PendingRefresh>();

export function setPendingRefresh(
	request: Request,
	refresh: PendingRefresh,
): void {
	pendingRefreshes.set(request, refresh);
}

export function getPendingRefresh(request: Request): PendingRefresh | undefined {
	return pendingRefreshes.get(request);
}

export function clearPendingRefresh(request: Request): void {
	pendingRefreshes.delete(request);
}

/**
 * Returns a pending refresh and removes it from the request-scoped store.
 */
export function takePendingRefresh(request: Request): PendingRefresh | undefined {
	const refresh = pendingRefreshes.get(request);
	if (refresh) {
		pendingRefreshes.delete(request);
	}
	return refresh;
}
