import {
	createAuthMiddleware,
	isAPIError,
} from "better-auth/api";
import type { HookMatchContext } from "./hooks";
import { clearTokenFromHeaders } from "./token-deliver";
import type { ResolvedScjwtOptions } from "./types";

export function isSignOutPath(path: string): boolean {
	return path === "/sign-out";
}

export function isRevokeSessionsPath(path: string): boolean {
	return path === "/revoke-sessions";
}

export function isRevokeSessionPath(path: string): boolean {
	return path === "/revoke-session";
}

export function signOutMatcher(context: HookMatchContext): boolean {
	return isSignOutPath(context.path ?? "");
}

export function revokeSessionsMatcher(context: HookMatchContext): boolean {
	return isRevokeSessionsPath(context.path ?? "");
}

export function revokeSessionMatcher(context: HookMatchContext): boolean {
	return isRevokeSessionPath(context.path ?? "");
}

/**
 * After-hooks that clear the SCJWT cookie or `set-auth-token` header on sign-out and revoke.
 */
export function createRevokeClearAfterHooks(options: ResolvedScjwtOptions): {
	after: {
		matcher:
			| typeof signOutMatcher
			| typeof revokeSessionsMatcher
			| typeof revokeSessionMatcher;
		handler: ReturnType<typeof createAuthMiddleware>;
	}[];
} {
	return {
		after: [
			{
				matcher: signOutMatcher,
				handler: createAlwaysClearHandler(options),
			},
			{
				matcher: revokeSessionsMatcher,
				handler: createAlwaysClearHandler(options),
			},
			{
				matcher: revokeSessionMatcher,
				handler: createRevokeSessionClearHandler(options),
			},
		],
	};
}

function createAlwaysClearHandler(
	options: ResolvedScjwtOptions,
): ReturnType<typeof createAuthMiddleware> {
	return createAuthMiddleware(async (ctx) => {
		if (isAPIError(ctx.context.returned)) {
			return { context: ctx };
		}

		ctx.context.responseHeaders ??= new Headers();
		clearTokenFromHeaders(ctx.context.responseHeaders, {
			tokenPlacement: options.tokenPlacement,
			cookieName: options.cookieName,
			createAuthCookie: ctx.context.createAuthCookie,
		});

		return { context: ctx };
	});
}

function createRevokeSessionClearHandler(
	options: ResolvedScjwtOptions,
): ReturnType<typeof createAuthMiddleware> {
	return createAuthMiddleware(async (ctx) => {
		if (isAPIError(ctx.context.returned)) {
			return { context: ctx };
		}

		const revokedToken = (ctx.body as { token?: string } | undefined)?.token;
		const currentToken = ctx.context.session?.session?.token;
		if (!revokedToken || revokedToken !== currentToken) {
			return { context: ctx };
		}

		ctx.context.responseHeaders ??= new Headers();
		clearTokenFromHeaders(ctx.context.responseHeaders, {
			tokenPlacement: options.tokenPlacement,
			cookieName: options.cookieName,
			createAuthCookie: ctx.context.createAuthCookie,
		});

		return { context: ctx };
	});
}
