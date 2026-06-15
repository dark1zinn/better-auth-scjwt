import {
	createAuthMiddleware,
	getSessionFromCtx,
	isAPIError,
} from "better-auth/api";
import { stripBetterAuthCookiesFromHeaders } from "./cookie-strip";
import { computeJwtExpiresInSeconds } from "./effective-expiry";
import { computeFingerprint } from "./fingerprint";
import { setIssuanceToken } from "./issuance-state";
import { signJwtFromParts } from "./jwt";
import { getRequestFingerprintInput } from "./request-context";
import { applyTokenToHeaders } from "./token-deliver";
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
 * After-hooks for session JWT issuance on successful sign-in / sign-up.
 */
export function createIssuanceAfterHooks(options: ResolvedScjwtOptions): {
	after: {
		matcher: typeof sessionIssuanceMatcher;
		handler: ReturnType<typeof createAuthMiddleware>;
	}[];
} {
	return {
		after: [
			{
				matcher: sessionIssuanceMatcher,
				handler: createIssuanceHandler(options),
			},
		],
	};
}

function createIssuanceHandler(
	options: ResolvedScjwtOptions,
): ReturnType<typeof createAuthMiddleware> {
	return createAuthMiddleware(async (ctx) => {
		if (isAPIError(ctx.context.returned)) {
			return { context: ctx };
		}

		const sessionResult = await getSessionFromCtx(ctx);
		const session = sessionResult?.session;
		if (!session?.id || !session.userId) {
			return { context: ctx };
		}

		const headers = ctx.headers ?? new Headers();
		const { ip, ua, platform } = getRequestFingerprintInput(
			headers,
			ctx.context.options,
		);
		const fingerprint = computeFingerprint(ip, ua, platform);

		const issuedAt = Math.floor(Date.now() / 1000);
		const expiresInSeconds = computeJwtExpiresInSeconds(
			issuedAt,
			options.expiresInSeconds,
			session.expiresAt,
		);

		if (expiresInSeconds <= 0) {
			return { context: ctx };
		}

		const token = await signJwtFromParts({
			jwtSecret: options.jwtSecret,
			issuer: options.issuer,
			userId: session.userId,
			fingerprint,
			sessionId: session.id,
			expiresInSeconds,
			issuedAt,
		});

		setIssuanceToken(ctx.context as Record<string, unknown>, token);

		ctx.context.responseHeaders ??= new Headers();
		stripBetterAuthCookiesFromHeaders(
			ctx.context.responseHeaders,
			ctx.context.authCookies,
		);
		applyTokenToHeaders(ctx.context.responseHeaders, {
			token,
			tokenPlacement: options.tokenPlacement,
			expiresInSeconds,
			cookieName: options.cookieName,
			createAuthCookie: ctx.context.createAuthCookie,
		});

		return { context: ctx };
	});
}
