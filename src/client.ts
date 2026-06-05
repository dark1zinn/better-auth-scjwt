import type { BetterAuthClientPlugin } from "better-auth/client";
import { PLUGIN_ID } from "./plugin/constants";
import type { scjwt } from "./plugin/index";

type ScjwtServerPlugin = ReturnType<typeof scjwt>;

/**
 * Better Auth client plugin for SCJWT. Pairs with the server {@link scjwt}
 * plugin for `$InferServerPlugin` type inference. Token refresh is handled
 * server-side via `onResponse` when `slidingSession` is enabled.
 */
export function scjwtClient(): BetterAuthClientPlugin & {
	id: typeof PLUGIN_ID;
	$InferServerPlugin: ScjwtServerPlugin;
} {
	return {
		id: PLUGIN_ID,
		$InferServerPlugin: {} as ScjwtServerPlugin,
	};
}
