import type { BetterAuthOptions, BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import {
	BEARER_PLUGIN_ID,
	DEFAULT_FINGERPRINT_MODE,
	DEFAULT_TOKEN_PLACEMENT,
	FINALIZER_PLUGIN_ID,
	FINGERPRINT_PREFIX_DEFAULTS,
	MULTI_SESSION_PLUGIN_ID,
	PLUGIN_ID,
} from "./constants";
import { createScjwtHooks } from "./hooks";
import type {
	ResolvedFingerprintOptions,
	ResolvedScjwtOptions,
	ScjwtFingerprintOptions,
	ScjwtOptions,
} from "./types";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		scjwt: {
			creator: typeof scjwt;
		};
	}
}

/**
 * Better Auth plugin that replaces the client-visible session token with a
 * Session-Centric JWT while Better Auth's session store stays authoritative.
 */
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
			assertSupportedPlugins(plugins);
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
							// Plugins appended by other plugins' `init` only appear in the
							// resolved list, so re-check unsupported plugins here as well.
							assertSupportedPlugins(plugins);
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
 * Rejects plugins that turn Better Auth's raw native session token into a
 * credential SCJWT never verifies, bypassing fingerprint and claim checks:
 * bearer() reads it from `Authorization`, and multiSession() keeps it in its
 * own cookies and activates it with `/multi-session/set-active`.
 */
function assertSupportedPlugins(plugins: BetterAuthPlugin[]): void {
	if (plugins.some((plugin) => plugin.id === BEARER_PLUGIN_ID)) {
		throw new Error(
			'[scjwt] the Better Auth bearer() plugin cannot be combined with scjwt(); use scjwt({ tokenPlacement: "header" }) for Authorization: Bearer transport.',
		);
	}
	if (plugins.some((plugin) => plugin.id === MULTI_SESSION_PLUGIN_ID)) {
		throw new Error(
			"[scjwt] the Better Auth multiSession() plugin cannot be combined with scjwt(); it keeps raw native session tokens in cookies that authenticate without SCJWT's fingerprint and claim checks.",
		);
	}
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

/** Applies defaults to the plugin options and rejects unsupported values. */
function resolveOptions(options: ScjwtOptions): ResolvedScjwtOptions {
	const tokenPlacement = options.tokenPlacement ?? DEFAULT_TOKEN_PLACEMENT;
	if (tokenPlacement !== "cookie" && tokenPlacement !== "header") {
		throw new Error('[scjwt] tokenPlacement must be "cookie" or "header".');
	}
	if ("fingerprintMode" in options) {
		throw new Error(
			'[scjwt] fingerprintMode was replaced by fingerprint.mode ("strict", "dynamic" or "loose").',
		);
	}
	return {
		tokenPlacement,
		fingerprint: resolveFingerprintOptions(options.fingerprint),
		getCustomClaims: options.getCustomClaims,
	};
}

/** Applies the mode's prefix defaults; explicit prefixes win. */
function resolveFingerprintOptions(
	options: ScjwtFingerprintOptions | undefined,
): ResolvedFingerprintOptions {
	if (options !== undefined && (typeof options !== "object" || options === null)) {
		throw new Error('[scjwt] fingerprint must be an object such as { mode: "dynamic" }.');
	}
	const mode = options?.mode ?? DEFAULT_FINGERPRINT_MODE;
	if (mode !== "strict" && mode !== "dynamic" && mode !== "loose") {
		throw new Error('[scjwt] fingerprint.mode must be "strict", "dynamic" or "loose".');
	}
	const defaults = FINGERPRINT_PREFIX_DEFAULTS[mode];
	return {
		mode,
		ipv4Prefix: assertPrefix("ipv4Prefix", options?.ipv4Prefix ?? defaults.ipv4Prefix, 32),
		ipv6Prefix: assertPrefix("ipv6Prefix", options?.ipv6Prefix ?? defaults.ipv6Prefix, 128),
	};
}

/** Returns `value` when it is an integer prefix length from 0 to `max`. */
function assertPrefix(name: string, value: number, max: number): number {
	if (!Number.isInteger(value) || value < 0 || value > max) {
		throw new Error(`[scjwt] fingerprint.${name} must be an integer from 0 to ${max}.`);
	}
	return value;
}
