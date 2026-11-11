// Type-checked inside a temporary project that installed the packed tarball; see scripts/check-package.ts.
import type { UserSession } from "@thallesp/nestjs-better-auth";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthClient } from "better-auth/client";
import {
	scjwt,
	type FingerprintMode,
	type JsonValue,
	type ScjwtJwtPayload,
	type ScjwtOptions,
	type TokenPlacement,
} from "better-auth-scjwt";
import { scjwtClient } from "better-auth-scjwt/client";

type IsAny<T> = 0 extends 1 & T ? true : false;

const options: ScjwtOptions = {
	tokenPlacement: "header" satisfies TokenPlacement,
	fingerprintMode: "ip-only" satisfies FingerprintMode,
	getCustomClaims: ({ user }) => ({ plan: (user.plan as JsonValue) ?? null }),
};

export const auth = betterAuth({
	database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
	user: { additionalFields: { plan: { type: "string", required: false } } },
	plugins: [scjwt(options)],
});

type Session = NonNullable<Awaited<ReturnType<typeof auth.api.getSession>>>;
declare const session: Session;
export const sessionId: string = session.session.id;
export const email: string = session.user.email;
export const plan: string | null | undefined = session.user.plan;
// @ts-expect-error Unknown user fields must not be inferred as any.
session.user.nonexistent;

declare const nestSession: UserSession<typeof auth>;
export const nestEmail: string = nestSession.user.email;
// @ts-expect-error Nest's UserSession keeps Better Auth's inferred shape.
nestSession.user.nonexistent;

export async function registeredPlugin() {
	const plugin = (await auth.$context).getPlugin("scjwt");
	const notAny: IsAny<typeof plugin> = false;
	return notAny;
}

declare const payload: ScjwtJwtPayload;
export const remember: boolean = payload.remember;
export const sid: string = payload.sid;

export const client = createAuthClient({ plugins: [scjwtClient()] });
const clientId: "scjwt" = scjwtClient().id;
export { clientId };
