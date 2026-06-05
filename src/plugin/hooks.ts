import { createAuthMiddleware } from "better-auth/api";
import type { ResolvedScjwtOptions } from "./types";

export interface HookMatchContext {
	path?: string;
}

/**
 * Returns true for Better Auth routes that create a session after successful auth.
 */
export function isSessionIssuancePath(path: string): boolean {
	return path.startsWith("/sign-in/") || path.startsWith("/sign-up/");
}

/**
 * `hooks.after` matcher for sign-in and sign-up success responses.
 */
export function sessionIssuanceMatcher(context: HookMatchContext): boolean {
	const path = context.path ?? "";
	return isSessionIssuancePath(path);
}

/**
 * After-hooks scaffold for session JWT issuance (handler wired in todos 16–17).
 */
export function createIssuanceAfterHooks(_options: ResolvedScjwtOptions): {
	after: {
		matcher: typeof sessionIssuanceMatcher;
		handler: ReturnType<typeof createAuthMiddleware>;
	}[];
} {
	return {
		after: [
			{
				matcher: sessionIssuanceMatcher,
				handler: createIssuanceHandler(),
			},
		],
	};
}

function createIssuanceHandler(): ReturnType<typeof createAuthMiddleware> {
	return createAuthMiddleware(async (ctx) => {
		return { context: ctx };
	});
}
