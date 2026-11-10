import type { BetterAuthOptions, BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import {
	BEARER_PLUGIN_ID,
	DEFAULT_FINGERPRINT_MODE,
	DEFAULT_TOKEN_PLACEMENT,
	FINALIZER_PLUGIN_ID,
	PLUGIN_ID,
} from "./constants";
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
	const { before = [], after = [] } = createScjwtHooks(resolved);
	/**
	 * Issues SCJWTs from the final request outcome. `init` appends it after
	 * every registered plugin so later plugin after-hooks (two-factor
	 * challenges, denials, session replacement) run before issuance.
	 */
	const finalizer = {
		id: FINALIZER_PLUGIN_ID,
		hooks: { after },
	} satisfies BetterAuthPlugin;
	const verifiedPluginLists = new WeakSet<BetterAuthPlugin[]>();
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
			const plugins = context.options.plugins ?? [];
			if (
				plugins.filter((plugin) => plugin.id === PLUGIN_ID).length !== 1 ||
				plugins.some((plugin) => plugin.id === FINALIZER_PLUGIN_ID)
			) {
				throw new Error("[scjwt] register scjwt() exactly once.");
			}
			// bearer() turns a native session token from `Authorization` into a session
			// cookie that SCJWT never verifies, bypassing fingerprint and claim checks.
			if (plugins.some((plugin) => plugin.id === BEARER_PLUGIN_ID)) {
				throw new Error(
					'[scjwt] the Better Auth bearer() plugin cannot be combined with scjwt(); use scjwt({ tokenPlacement: "header" }) for Authorization: Bearer transport.',
				);
			}
			return {
				options: { plugins: [finalizer] } satisfies Partial<BetterAuthOptions>,
			};
		},
		hooks: {
			before: [
				{
					matcher: () => true,
					handler: createAuthMiddleware(async (ctx) => {
						const plugins = ctx.context.options.plugins ?? [];
						if (!verifiedPluginLists.has(plugins)) {
							assertFinalizerIsTerminal(plugins);
							verifiedPluginLists.add(plugins);
						}
					}),
				},
				...before,
			],
		},
	} satisfies BetterAuthPlugin;
}

/**
 * Better Auth runs plugin after-hooks in plugin order. Issuance is only safe
 * when no after-hook can still change the outcome, so a plugin list where
 * another `init` appended after-hooks behind the finalizer is rejected
 * before the endpoint runs.
 */
function assertFinalizerIsTerminal(plugins: BetterAuthPlugin[]): void {
	const finalizerIndex = plugins.findIndex(
		(plugin) => plugin.id === FINALIZER_PLUGIN_ID,
	);
	if (
		finalizerIndex === -1 ||
		plugins
			.slice(finalizerIndex + 1)
			.some((plugin) => (plugin.hooks?.after?.length ?? 0) > 0)
	) {
		throw new Error(
			"[scjwt] session finalizer must run after all plugin after-hooks.",
		);
	}
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
