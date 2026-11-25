import type { GenericEndpointContext } from "@better-auth/core";
import type { AuthContext, BetterAuthPlugin, Session, User } from "better-auth";
import { createAuthMiddleware, isAPIError } from "better-auth/api";
import { expireCookie, parseCookies } from "better-auth/cookies";
import { serializeSignedCookie } from "better-call";
import { NONPERSISTENT_SESSION_SECONDS } from "./constants";
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
	hasLiveSetCookie,
	isHeaderOnlyNativeCookie,
	removePendingSessionTransport,
	SET_AUTH_TOKEN_HEADER,
} from "./token-deliver";
import { extractToken } from "./token-extract";
import type {
	ResolvedScjwtOptions,
	ScjwtClaimContext,
	ScjwtJwtPayload,
} from "./types";

/**
 * What the before hook decided about the presented SCJWT, read by the session
 * finalizer of the same request. Keyed by the request's `AuthContext`, which
 * Better Auth shares between a request's before and after hooks.
 */
type RequestState =
	| { kind: "authenticated"; sessionId: string }
	| { kind: "signed-out" };

const requestStates = new WeakMap<AuthContext, RequestState>();

/**
 * Builds SCJWT's universal hooks. The before hook authenticates a presented
 * SCJWT through Better Auth's session lifecycle and injects the native
 * session cookie; a presented SCJWT that cannot authenticate is removed so
 * the request continues signed out. The after hook is the session finalizer:
 * `scjwt()` installs it on an internal plugin appended after every registered
 * plugin, so it observes the final `ctx.context.newSession` and result and
 * issues a replacement SCJWT only when the request ultimately succeeds.
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
					const authCookies = ctx.context.authCookies;
					const token = extractToken({
						tokenPlacement: options.tokenPlacement,
						cookieName: authCookies.sessionToken.name,
						headers: sourceHeaders,
					});
					if (!token) {
						if (options.tokenPlacement === "header") {
							const headers = stripNativeSessionCookies(
								sourceHeaders,
								authCookies,
							);
							if (headers) {
								return { context: { headers } };
							}
						}
						return;
					}

					const authenticated = await authenticateToken(
						ctx.context,
						options,
						token,
						sourceHeaders,
						ctx.request,
					);
					if (!authenticated) {
						// Like an invalid Better Auth session cookie: the request continues
						// without a session, so sign-in and sign-up still work and
						// session-protected endpoints answer 401 on their own.
						requestStates.set(ctx.context, { kind: "signed-out" });
						return {
							context: {
								headers: withoutSessionCredentials(
									sourceHeaders,
									authCookies,
									options.tokenPlacement,
								),
							},
						};
					}

					const { session, user, nativeToken, payload } = authenticated;
					ctx.context.session = { session, user };
					requestStates.set(ctx.context, {
						kind: "authenticated",
						sessionId: session.id,
					});
					const headers = await buildAuthenticatedRequestHeaders(
						sourceHeaders,
						authCookies,
						ctx.context.secret,
						nativeToken,
						payload.remember,
					);
					return { context: { headers } };
				}),
			},
		],
		after: [
			{
				matcher: () => true,
				handler: createAuthMiddleware(async (ctx) => {
					const state = requestStates.get(ctx.context);
					requestStates.delete(ctx.context);
					const newSession = ctx.context.newSession;
					if (!newSession) {
						// A later hook withdrew the session (for example a pending two-factor
						// challenge): drop the live native credential written for it so it
						// neither leaks nor overwrites the SCJWT the client already holds.
						const pending = ctx.context.responseHeaders;
						if (
							pending &&
							hasLiveSetCookie(pending, ctx.context.authCookies.sessionToken.name)
						) {
							removePendingSessionTransport(pending, ctx.context.authCookies);
						}
						if (state?.kind === "signed-out" && options.tokenPlacement === "cookie") {
							// The browser cannot drop an HttpOnly SCJWT on its own.
							clearSessionTransport(ctx);
						}
						return;
					}
					const returned = ctx.context.returned;
					if (
						(isAPIError(returned) && returned.statusCode >= 400) ||
						(returned instanceof Response && returned.status >= 400)
					) {
						if (
							state?.kind === "authenticated" &&
							state.sessionId === newSession.session.id
						) {
							// Only the presented session was refreshed: keep its SCJWT valid
							// and drop the replacement instead of logging the client out.
							if (ctx.context.responseHeaders) {
								removePendingSessionTransport(
									ctx.context.responseHeaders,
									ctx.context.authCookies,
								);
							}
						} else {
							clearSessionTransport(ctx);
						}
						return;
					}
					const headers =
						ctx.request?.headers ?? ctx.headers ?? new Headers();
					const input = getRequestFingerprintInput(
						headers,
						ctx.context.options,
						options.fingerprintMode,
					);
					const remember = !hasLiveSetCookie(
						ctx.context.responseHeaders,
						ctx.context.authCookies.dontRememberToken.name,
					);
					const issuedAt = Math.floor(Date.now() / 1000);
					const expiresAt = Math.min(
						Math.floor(new Date(newSession.session.expiresAt).getTime() / 1000),
						issuedAt + tokenLifetime(remember, ctx.context),
					);
					if (expiresAt <= issuedAt) {
						clearSessionTransport(ctx);
						return;
					}
					let token: string;
					try {
						const customClaims = options.getCustomClaims
							? await resolveCustomClaims(options, {
									session: newSession.session,
									user: newSession.user,
									request: ctx.request,
								})
							: undefined;
						token = await signJwtFromParts({
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
							remember,
							customClaims,
						});
					} catch (error) {
						// Never let the opaque native session cookie stand in for an
						// SCJWT that could not be issued.
						clearSessionTransport(ctx);
						throw error;
					}
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

interface AuthenticatedToken {
	session: Session & Record<string, unknown>;
	user: User & Record<string, unknown>;
	nativeToken: string;
	payload: ScjwtJwtPayload;
}

/**
 * Authenticates a presented SCJWT: signature, issuer and claims, then the
 * session through Better Auth's lifecycle, the effective expiry, subject,
 * device fingerprint and custom claims. Returns `null` when the token cannot
 * authenticate; storage and resolver failures propagate.
 */
async function authenticateToken(
	context: AuthContext,
	options: ResolvedScjwtOptions,
	token: string,
	headers: Headers,
	request: Request | undefined,
): Promise<AuthenticatedToken | null> {
	const payload = await verifyRequestToken(
		context,
		token,
		options.getCustomClaims !== undefined,
	);
	if (!payload) {
		return null;
	}
	const resolved = await resolveAuthoritativeSession(context, payload.sid);
	if (!resolved) {
		return null;
	}
	const { session, user, nativeToken } = resolved;

	const sessionExpiresAt = Math.floor(
		new Date(session.expiresAt).getTime() / 1000,
	);
	const maximumTokenExpiry = Math.min(
		sessionExpiresAt,
		payload.iat + tokenLifetime(payload.remember, context),
	);
	if (
		sessionExpiresAt <= Math.floor(Date.now() / 1000) ||
		payload.exp > maximumTokenExpiry ||
		payload.sub !== `user:${session.userId}`
	) {
		return null;
	}

	const requestFingerprint = getRequestFingerprintInput(
		headers,
		context.options,
		options.fingerprintMode,
	);
	const expectedFingerprint = await computeFingerprint(
		requestFingerprint.ip,
		requestFingerprint.ua,
		requestFingerprint.platform,
	);
	if (payload.fp !== expectedFingerprint) {
		return null;
	}

	if (options.getCustomClaims) {
		const expectedClaims = await resolveCustomClaims(options, {
			session,
			user,
			request,
		});
		if (!jsonValuesEqual(getCustomClaims(payload), expectedClaims)) {
			return null;
		}
	}
	return { session, user, nativeToken, payload };
}

/**
 * Longest SCJWT lifetime for a session: Better Auth's `session.expiresIn` for
 * remembered sessions, and the fixed one-day lifetime Better Auth gives
 * `rememberMe: false` sessions, which never refresh.
 */
function tokenLifetime(remember: boolean, context: AuthContext): number {
	return remember ? context.sessionConfig.expiresIn : NONPERSISTENT_SESSION_SECONDS;
}

/**
 * Builds the request-only headers Better Auth's endpoint sees for a verified
 * SCJWT: the signed native session cookie replaces the presented credential,
 * the `dontRemember` marker is reconstructed solely from the signed
 * `remember` claim so a caller-supplied marker can neither add nor remove
 * Better Auth's no-refresh policy, and cookie-cache (`session_data`) cookies
 * are dropped so Better Auth reads the session and user from its store
 * instead of a client-held snapshot.
 */
async function buildAuthenticatedRequestHeaders(
	sourceHeaders: Headers,
	authCookies: AuthContext["authCookies"],
	secret: string,
	nativeToken: string,
	remember: boolean,
): Promise<Headers> {
	const cookies = parseCookies(sourceHeaders.get("cookie") ?? "");
	const sessionDataChunkPrefix = `${authCookies.sessionData.name}.`;
	for (const name of cookies.keys()) {
		if (
			name === authCookies.dontRememberToken.name ||
			name === authCookies.sessionData.name ||
			name.startsWith(sessionDataChunkPrefix)
		) {
			cookies.delete(name);
		}
	}
	cookies.set(
		authCookies.sessionToken.name,
		await signRequestCookieValue(nativeToken, secret),
	);
	if (!remember) {
		cookies.set(
			authCookies.dontRememberToken.name,
			await signRequestCookieValue("true", secret),
		);
	}
	const headers = new Headers(sourceHeaders);
	headers.set("cookie", serializeRequestCookies(cookies));
	return headers;
}

/**
 * Request-only headers for a presented SCJWT that cannot authenticate: the
 * credential and every native session cookie are removed, so neither the
 * token nor a stray native cookie or cached snapshot can stand in for it.
 */
function withoutSessionCredentials(
	sourceHeaders: Headers,
	authCookies: AuthContext["authCookies"],
	tokenPlacement: ResolvedScjwtOptions["tokenPlacement"],
): Headers {
	const headers =
		stripNativeSessionCookies(sourceHeaders, authCookies) ??
		new Headers(sourceHeaders);
	if (tokenPlacement === "header") {
		headers.delete("authorization");
	}
	return headers;
}

/** Signs `value` the way Better Auth's `setSignedCookie` stores it. */
async function signRequestCookieValue(value: string, secret: string): Promise<string> {
	const serialized = (await serializeSignedCookie("", value, secret)).replace("=", "");
	try {
		return decodeURIComponent(serialized);
	} catch {
		// The serializer currently percent-encodes. Keep the raw value if that changes.
		return serialized;
	}
}

/** Serializes request cookies into a `Cookie` header value. */
function serializeRequestCookies(cookies: Map<string, string>): string {
	return [...cookies]
		.map(([name, value]) => `${name}=${encodeURIComponent(value)}`)
		.join("; ");
}

/**
 * Removes every pending authentication transport for a session that will not
 * receive an SCJWT: live native session cookies are replaced by clearing
 * cookies and any pending `set-auth-token` header is dropped. The backing
 * session row is left to Better Auth.
 */
function clearSessionTransport(
	ctx: GenericEndpointContext & { context: { responseHeaders?: Headers } },
): void {
	expireCookie(ctx, ctx.context.authCookies.sessionToken);
	expireCookie(ctx, ctx.context.authCookies.sessionData);
	expireCookie(ctx, ctx.context.authCookies.dontRememberToken);
	ctx.context.responseHeaders?.delete(SET_AUTH_TOKEN_HEADER);
}

/**
 * Removes native session cookies (session token, `dontRemember`, session data
 * and its chunks) from a request's `Cookie` header. Returns `null` when
 * nothing was removed.
 */
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
	headers.set("cookie", serializeRequestCookies(cookies));
	return headers;
}

/** Verifies the presented SCJWT; any verification failure yields `null`. */
async function verifyRequestToken(
	context: AuthContext,
	token: string,
	allowCustomClaims: boolean,
): Promise<ScjwtJwtPayload | null> {
	try {
		return await verifyJwt({
			token,
			secretConfig: context.secretConfig,
			issuer: context.baseURL,
			allowCustomClaims,
		});
	} catch {
		return null;
	}
}

/** Runs the configured custom-claims resolver and validates its result. */
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
 * eviction and revocation are honored even when the database row is
 * preserved. Returns `null` when the session is not live; storage failures
 * propagate.
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
		return null;
	}
	const resolved = await context.internalAdapter.findSession(candidate.token);
	if (!resolved || resolved.session.id !== sessionId) {
		return null;
	}
	return { ...resolved, nativeToken: candidate.token };
}
