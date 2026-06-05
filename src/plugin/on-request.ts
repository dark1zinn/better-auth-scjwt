import type { AuthContext } from "better-auth";
import { extractTokenFromRequest } from "./token-extract";
import type { ResolvedScjwtOptions } from "./types";

export type OnRequestHandler = (
	request: Request,
	context: AuthContext,
) => Promise<void>;

/**
 * Gateway guard entry point. Falls through when no SCJWT is present.
 */
export function createOnRequest(options: ResolvedScjwtOptions): OnRequestHandler {
	return async (request, context) => {
		const token = extractTokenFromRequest(request, {
			tokenPlacement: options.tokenPlacement,
			cookieName: options.cookieName,
		});

		if (!token) {
			return;
		}

		await handleAuthenticatedRequest(request, context, options, token);
	};
}

async function handleAuthenticatedRequest(
	request: Request,
	context: AuthContext,
	options: ResolvedScjwtOptions,
	token: string,
): Promise<void> {
	void request;
	void context;
	void options;
	void token;
}
