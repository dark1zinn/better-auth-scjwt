import type { AuthContext } from "better-auth";
import { computeFingerprint } from "./fingerprint";
import { verifyJwt } from "./jwt";
import { getRequestFingerprintInput } from "./request-context";
import { setPendingRefresh } from "./request-state";
import { refreshSlidingSession } from "./sliding-session";
import { loadSessionIntoContext } from "./session-bridge";
import { extractTokenFromRequest } from "./token-extract";
import type { ResolvedScjwtOptions, ScjwtJwtPayload } from "./types";
import {
	interruptWithUnauthorized,
	type OnRequestInterrupt,
} from "./unauthorized-response";

export type OnRequestHandler = (
	request: Request,
	context: AuthContext,
) => Promise<OnRequestInterrupt | void>;

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

		return handleAuthenticatedRequest(request, context, options, token);
	};
}

async function handleAuthenticatedRequest(
	request: Request,
	context: AuthContext,
	options: ResolvedScjwtOptions,
	token: string,
): Promise<OnRequestInterrupt | void> {
	const payload = await verifyRequestToken(token, options);
	if (!payload) {
		return interruptWithUnauthorized("Invalid or expired session token.");
	}

	const fingerprintMismatch = await handleFingerprintCheck(
		request,
		context,
		payload,
	);
	if (fingerprintMismatch) {
		return fingerprintMismatch;
	}

	const sessionError = await loadSessionIntoContext(context, payload);
	if (sessionError) {
		return sessionError;
	}

	await handleSlidingSessionRefresh(request, context, options, payload);
}

async function handleSlidingSessionRefresh(
	request: Request,
	context: AuthContext,
	options: ResolvedScjwtOptions,
	payload: ScjwtJwtPayload,
): Promise<void> {
	const activeSession = context.session;
	if (!activeSession) {
		return;
	}

	const refreshedToken = await refreshSlidingSession({
		adapter: context.adapter,
		options,
		payload,
		userId: activeSession.session.userId,
		fingerprint: payload.fp,
	});

	if (!refreshedToken) {
		return;
	}

	const nowSeconds = Math.floor(Date.now() / 1000);
	activeSession.session.expiresAt = new Date(
		(nowSeconds + options.expiresInSeconds) * 1000,
	);

	setPendingRefresh(request, {
		token: refreshedToken,
		placement: options.tokenPlacement,
	});
}

async function verifyRequestToken(
	token: string,
	options: ResolvedScjwtOptions,
): Promise<ScjwtJwtPayload | null> {
	try {
		return await verifyJwt({
			token,
			jwtSecret: options.jwtSecret,
			issuer: options.issuer,
		});
	} catch {
		return null;
	}
}

async function handleFingerprintCheck(
	request: Request,
	context: AuthContext,
	payload: ScjwtJwtPayload,
): Promise<OnRequestInterrupt | void> {
	const { ip, ua, platform } = getRequestFingerprintInput(
		request.headers,
		context.options,
	);
	const currentFingerprint = computeFingerprint(ip, ua, platform);

	if (currentFingerprint === payload.fp) {
		return;
	}

	await context.adapter.delete({
		model: "session",
		where: [{ field: "id", value: payload.sid }],
	});

	return interruptWithUnauthorized(
		"Machine fingerprint mismatch. Session revoked.",
	);
}
