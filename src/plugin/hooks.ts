import type { AuthContext, BetterAuthPlugin, Session } from "better-auth";
import { APIError, createAuthMiddleware, isAPIError } from "better-auth/api";
import {
	expireCookie,
	parseCookies,
	setRequestCookie,
} from "better-auth/cookies";
import { serializeSignedCookie } from "better-call";
import { computeFingerprint } from "./fingerprint";
import {
	getCustomClaims,
	jsonValuesEqual,
	signJwtFromParts,
	validateCustomClaims,
	verifyJwt,
	type CustomClaims,
} from "./jwt";
import { getRequestFingerprintInput } from "./request-context";
import {
	deliverSessionToken,
	isHeaderOnlyNativeCookie,
} from "./token-deliver";
import { extractToken } from "./token-extract";
import type {
	ResolvedScjwtOptions,
	ScjwtClaimContext,
	ScjwtJwtPayload,
} from "./types";

/**
 * Builds SCJWT's universal hooks. The before hook authenticates a presented
 * SCJWT through Better Auth's session lifecycle and injects the native
 * session cookie; the after hook issues a replacement SCJWT whenever a
 * successful response carries `ctx.context.newSession`.
 */
export function createScjwtHooks(
	options: ResolvedScjwtOptions,
): NonNullable<BetterAuthPlugin["hooks"]> {
	return {
		before: [
			{
				matcher: () => true,
				handler: createAuthMiddleware(async (ctx) => {
					const sourceHeaders =
						ctx.request?.headers ?? ctx.headers ?? new Headers();
					const token = extractToken({
						tokenPlacement: options.tokenPlacement,
						cookieName: ctx.context.authCookies.sessionToken.name,
						headers: sourceHeaders,
					});
					if (!token) {
						if (options.tokenPlacement === "header") {
							const headers = stripNativeSessionCookies(
								sourceHeaders,
								ctx.context.authCookies,
							);
							if (headers) {
								return { context: { headers } };
							}
						}
						return;
					}

					const payload = await verifyRequestToken(
						ctx.context,
						token,
						options.getCustomClaims !== undefined,
					);
					const { session, user, nativeToken } =
						await resolveAuthoritativeSession(ctx.context, payload.sid);

					const sessionExpiresAt = Math.floor(
						new Date(session.expiresAt).getTime() / 1000,
					);
					const maximumTokenExpiry = Math.min(
						sessionExpiresAt,
						payload.iat + ctx.context.sessionConfig.expiresIn,
					);
					if (
						sessionExpiresAt <= Math.floor(Date.now() / 1000) ||
						payload.exp > maximumTokenExpiry ||
						payload.sub !== `user:${session.userId}`
					) {
						unauthorized();
					}

					const requestFingerprint = getRequestFingerprintInput(
						sourceHeaders,
						ctx.context.options,
						options.fingerprintMode,
					);
					const expectedFingerprint = await computeFingerprint(
						requestFingerprint.ip,
						requestFingerprint.ua,
						requestFingerprint.platform,
					);
					if (payload.fp !== expectedFingerprint) {
						unauthorized();
					}

					if (options.getCustomClaims) {
						const expectedClaims = await resolveCustomClaims(options, {
							session,
							user,
							request: ctx.request,
						});
						if (!jsonValuesEqual(getCustomClaims(payload), expectedClaims)) {
							unauthorized();
						}
					}

					ctx.context.session = { session, user };
					const headers = new Headers(sourceHeaders);
					const serializedSessionToken = (
						await serializeSignedCookie("", nativeToken, ctx.context.secret)
					).replace("=", "");
					let signedSessionToken = serializedSessionToken;
					try {
						signedSessionToken = decodeURIComponent(serializedSessionToken);
					} catch {
						// The serializer currently percent-encodes. Keep the raw value if that changes.
					}
					setRequestCookie(
						headers,
						ctx.context.authCookies.sessionToken.name,
						signedSessionToken,
					);
					return { context: { headers } };
				}),
			},
		],
		after: [
			{
				matcher: () => true,
				handler: createAuthMiddleware(async (ctx) => {
					const newSession = ctx.context.newSession;
					if (!newSession) {
						return;
					}
					const returned = ctx.context.returned;
					if (
						(isAPIError(returned) && returned.statusCode >= 400) ||
						(returned instanceof Response && !returned.ok)
					) {
						expireCookie(ctx, ctx.context.authCookies.sessionToken);
						expireCookie(ctx, ctx.context.authCookies.sessionData);
						expireCookie(ctx, ctx.context.authCookies.dontRememberToken);
						return;
					}
					const headers =
						ctx.request?.headers ?? ctx.headers ?? new Headers();
					const input = getRequestFingerprintInput(
						headers,
						ctx.context.options,
						options.fingerprintMode,
					);
					const issuedAt = Math.floor(Date.now() / 1000);
					const expiresAt = Math.min(
						Math.floor(new Date(newSession.session.expiresAt).getTime() / 1000),
						issuedAt + ctx.context.sessionConfig.expiresIn,
					);
					if (expiresAt <= issuedAt) {
						return;
					}
					const customClaims = options.getCustomClaims
						? await resolveCustomClaims(options, {
								session: newSession.session,
								user: newSession.user,
								request: ctx.request,
							})
						: undefined;
					const token = await signJwtFromParts({
						secretConfig: ctx.context.secretConfig,
						issuer: ctx.context.baseURL,
						userId: newSession.session.userId,
						fingerprint: await computeFingerprint(
							input.ip,
							input.ua,
							input.platform,
						),
						sessionId: newSession.session.id,
						expiresAt,
						issuedAt,
						customClaims,
					});
					ctx.context.responseHeaders ??= new Headers();
					deliverSessionToken(
						ctx.context.responseHeaders,
						token,
						options.tokenPlacement,
						ctx.context.authCookies,
					);
				}),
			},
		],
	};
}

function stripNativeSessionCookies(
	sourceHeaders: Headers,
	authCookies: AuthContext["authCookies"],
): Headers | null {
	const cookieHeader = sourceHeaders.get("cookie");
	if (!cookieHeader) {
		return null;
	}
	const cookies = parseCookies(cookieHeader);
	let removed = false;
	for (const name of cookies.keys()) {
		if (isHeaderOnlyNativeCookie(name, authCookies)) {
			cookies.delete(name);
			removed = true;
		}
	}
	if (!removed) {
		return null;
	}
	const headers = new Headers(sourceHeaders);
	if (cookies.size === 0) {
		headers.set("cookie", "");
	} else {
		headers.set(
			"cookie",
			[...cookies]
				.map(([name, value]) => `${name}=${encodeURIComponent(value)}`)
				.join("; "),
		);
	}
	return headers;
}

async function verifyRequestToken(
	context: AuthContext,
	token: string,
	allowCustomClaims: boolean,
): Promise<ScjwtJwtPayload> {
	try {
		return await verifyJwt({
			token,
			secretConfig: context.secretConfig,
			issuer: context.baseURL,
			allowCustomClaims,
		});
	} catch {
		unauthorized();
	}
}

async function resolveCustomClaims(
	options: ResolvedScjwtOptions,
	context: ScjwtClaimContext,
): Promise<CustomClaims> {
	const claims = await options.getCustomClaims?.(context);
	validateCustomClaims(claims);
	return claims;
}

/**
 * Resolves a signed `sid` through Better Auth's lifecycle-aware session lookup.
 *
 * The durable row only maps the public session ID to its opaque native token;
 * `internalAdapter.findSession` then decides liveness, so secondary-storage
 * eviction and revocation are honored even when the database row is preserved.
 */
async function resolveAuthoritativeSession(
	context: AuthContext,
	sessionId: string,
) {
	const candidate = await context.adapter.findOne<Session>({
		model: "session",
		where: [{ field: "id", value: sessionId }],
	});
	if (!candidate) {
		unauthorized();
	}
	const resolved = await context.internalAdapter.findSession(candidate.token);
	if (!resolved || resolved.session.id !== sessionId) {
		unauthorized();
	}
	return { ...resolved, nativeToken: candidate.token };
}

function unauthorized(): never {
	throw APIError.fromStatus("UNAUTHORIZED");
}
