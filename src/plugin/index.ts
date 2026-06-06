import type { BetterAuthPlugin } from "better-auth";
import { PLUGIN_ID } from "./constants";
import { createDatabaseRequiredInit } from "./database-required";
import { createIssuanceAfterHooks } from "./hooks";
import { createOnRequest } from "./on-request";
import { createOnResponse } from "./on-response";
import { resolveOptions } from "./resolve-options";
import type { ResolvedScjwtOptions, ScjwtOptions } from "./types";

export function scjwt(userOptions: ScjwtOptions): BetterAuthPlugin {
	const options = resolveOptions(userOptions);
	return createPlugin(options);
}

function createPlugin(options: ResolvedScjwtOptions): BetterAuthPlugin {
	return {
		id: PLUGIN_ID,
		init: createDatabaseRequiredInit(),
		hooks: createIssuanceAfterHooks(options),
		onRequest: createOnRequest(options),
		onResponse: createOnResponse(options),
	} satisfies BetterAuthPlugin;
}
