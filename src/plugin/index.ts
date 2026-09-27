import type { BetterAuthPlugin } from "better-auth";
import { DEFAULT_FINGERPRINT_MODE, DEFAULT_TOKEN_PLACEMENT, PLUGIN_ID } from "./constants";
import { createScjwtHooks } from "./hooks";
import type { ResolvedScjwtOptions, ScjwtOptions } from "./types";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		scjwt: {
			creator: typeof scjwt;
		};
	}
}

export function scjwt(options: ScjwtOptions = {}): BetterAuthPlugin {
	const resolved = resolveOptions(options);
	return {
		id: PLUGIN_ID,
		options,
		init(context) {
			if (context.options.database === undefined) {
				throw new Error(
					"[scjwt] a Better Auth database is required; stateless sessions are unsupported.",
				);
			}
			if (
				context.options.secondaryStorage !== undefined &&
				context.options.session?.storeSessionInDatabase !== true
			) {
				throw new Error(
					"[scjwt] secondaryStorage requires session.storeSessionInDatabase: true so SCJWT sessions remain immediately revocable from the database.",
				);
			}
		},
		hooks: createScjwtHooks(resolved),
	} satisfies BetterAuthPlugin;
}

function resolveOptions(options: ScjwtOptions): ResolvedScjwtOptions {
	const tokenPlacement = options.tokenPlacement ?? DEFAULT_TOKEN_PLACEMENT;
	if (tokenPlacement !== "cookie" && tokenPlacement !== "header") {
		throw new Error('[scjwt] tokenPlacement must be "cookie" or "header".');
	}
	const fingerprintMode = options.fingerprintMode ?? DEFAULT_FINGERPRINT_MODE;
	if (fingerprintMode !== "strict" && fingerprintMode !== "ip-only") {
		throw new Error('[scjwt] fingerprintMode must be "strict" or "ip-only".');
	}
	return {
		tokenPlacement,
		fingerprintMode,
		getCustomClaims: options.getCustomClaims,
	};
}
