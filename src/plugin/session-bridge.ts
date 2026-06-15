import type { AuthContext, Session, User } from "better-auth";
import { isPastEffectiveExpiry } from "./effective-expiry";
import type { ScjwtJwtPayload } from "./types";
import {
	interruptWithUnauthorized,
	type OnRequestInterrupt,
} from "./unauthorized-response";

/**
 * Loads the backing session row and user, then assigns `context.session`.
 */
export async function loadSessionIntoContext(
	context: AuthContext,
	payload: ScjwtJwtPayload,
): Promise<OnRequestInterrupt | void> {
	const session = await context.adapter.findOne<Session>({
		model: "session",
		where: [{ field: "id", value: payload.sid }],
	});

	if (!session) {
		return interruptWithUnauthorized("Session not found.");
	}

	if (isPastEffectiveExpiry(payload.exp, session.expiresAt)) {
		return interruptWithUnauthorized("Session has expired.");
	}

	const expectedSubject = `user:${session.userId}`;
	if (payload.sub !== expectedSubject) {
		return interruptWithUnauthorized("Session subject mismatch.");
	}

	const user = await context.adapter.findOne<User>({
		model: "user",
		where: [{ field: "id", value: session.userId }],
	});

	if (!user) {
		return interruptWithUnauthorized("User not found.");
	}

	context.session = { session, user };
}
