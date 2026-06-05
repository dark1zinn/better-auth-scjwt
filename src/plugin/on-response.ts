import type { AuthContext } from "better-auth";
import { takePendingRefresh } from "./request-state";
import { deliverTokenToResponse } from "./token-deliver";
import type { ResolvedScjwtOptions } from "./types";

export type OnResponseHandler = (
	response: Response,
	context: AuthContext,
) => Promise<{ response: Response } | void>;

/**
 * Delivers a sliding-session JWT on the outgoing response when a refresh was queued.
 */
export function createOnResponse(
	options: ResolvedScjwtOptions,
): OnResponseHandler {
	return async (response, context) => {
		const pending = takePendingRefresh(context as Record<string, unknown>);
		if (!pending) {
			return;
		}

		return {
			response: deliverTokenToResponse(response, {
				token: pending.token,
				tokenPlacement: pending.placement,
				expiresInSeconds: options.expiresInSeconds,
				cookieName: options.cookieName,
				createAuthCookie: context.createAuthCookie,
			}),
		};
	};
}
