import type { AuthContext, Session } from "better-auth";
import { createAuthMiddleware, isAPIError } from "better-auth/api";
import { setRequestCookie } from "better-auth/cookies";
import { APIError, serializeSignedCookie } from "better-call";
import { computeFingerprint } from "./fingerprint";
import { signJwtFromParts, verifyJwt } from "./jwt";
import { getRequestFingerprintInput } from "./request-context";
import { deliverSessionToken } from "./token-deliver";
import { extractToken } from "./token-extract";
import type { ResolvedScjwtOptions, ScjwtJwtPayload } from "./types";

export function createScjwtHooks(options: ResolvedScjwtOptions) {
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
						return;
					}

					const payload = await verifyRequestToken(ctx.context, token);
					const session = await ctx.context.adapter.findOne<Session>({
						model: "session",
						where: [{ field: "id", value: payload.sid }],
					});
					if (!session) {
						unauthorized();
					}

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
					);
					if (
						payload.fp !==
						computeFingerprint(
							requestFingerprint.ip,
							requestFingerprint.ua,
							requestFingerprint.platform,
						)
					) {
						await ctx.context.internalAdapter.deleteSession(session.token);
						unauthorized();
					}

					const user = await ctx.context.internalAdapter.findUserById(
						session.userId,
					);
					if (!user) {
						unauthorized();
					}

					const resolvedSession = { session, user };
					ctx.context.session = resolvedSession;
					const headers = new Headers(sourceHeaders);
					const signedSessionToken = decodeURIComponent(
						(
							await serializeSignedCookie(
								"",
								session.token,
								ctx.context.secret,
							)
						).replace("=", ""),
					);
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
					if (isAPIError(ctx.context.returned)) {
						return;
					}
					if (
						ctx.context.returned instanceof Response &&
						!ctx.context.returned.ok
					) {
						return;
					}
					const newSession = ctx.context.newSession;
					if (!newSession) {
						return;
					}

					const headers =
						ctx.request?.headers ?? ctx.headers ?? new Headers();
					const input = getRequestFingerprintInput(
						headers,
						ctx.context.options,
					);
					const issuedAt = Math.floor(Date.now() / 1000);
					const expiresAt = Math.min(
						Math.floor(new Date(newSession.session.expiresAt).getTime() / 1000),
						issuedAt + ctx.context.sessionConfig.expiresIn,
					);
					if (expiresAt <= issuedAt) {
						return;
					}
					const token = await signJwtFromParts({
						secretConfig: ctx.context.secretConfig,
						issuer: ctx.context.baseURL,
						userId: newSession.session.userId,
						fingerprint: computeFingerprint(input.ip, input.ua, input.platform),
						sessionId: newSession.session.id,
						expiresAt,
						issuedAt,
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

async function verifyRequestToken(
	context: AuthContext,
	token: string,
): Promise<ScjwtJwtPayload> {
	try {
		return await verifyJwt({
			token,
			secretConfig: context.secretConfig,
			issuer: context.baseURL,
		});
	} catch {
		unauthorized();
	}
}

function unauthorized(): never {
	throw APIError.fromStatus("UNAUTHORIZED");
}
