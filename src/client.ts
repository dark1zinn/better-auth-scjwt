import type { BetterAuthClientPlugin } from "better-auth/client";
import { PLUGIN_ID } from "./plugin/constants";
import type { scjwt } from "./plugin/index";

type ScjwtServerPlugin = ReturnType<typeof scjwt>;

/** Better Auth client inference plugin for the SCJWT server plugin. */
export function scjwtClient(): BetterAuthClientPlugin & {
	id: typeof PLUGIN_ID;
	$InferServerPlugin: ScjwtServerPlugin;
} {
	return {
		id: PLUGIN_ID,
		$InferServerPlugin: {} as ScjwtServerPlugin,
	};
}
