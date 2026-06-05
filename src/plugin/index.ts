import type { BetterAuthPlugin } from "better-auth";
import { PLUGIN_ID } from "./constants";
import { createIssuanceAfterHooks } from "./hooks";
import { createOnRequest } from "./on-request";
import { resolveOptions } from "./resolve-options";
import type { ResolvedScjwtOptions, ScjwtOptions } from "./types";

export function scjwt(userOptions: ScjwtOptions): BetterAuthPlugin {
	const options = resolveOptions(userOptions);
	return createPlugin(options);
}

function createPlugin(options: ResolvedScjwtOptions): BetterAuthPlugin {
	return {
		id: PLUGIN_ID,
		hooks: createIssuanceAfterHooks(options),
		onRequest: createOnRequest(options),
	} satisfies BetterAuthPlugin;
}
