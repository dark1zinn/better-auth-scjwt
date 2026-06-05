import { defineConfig } from "tsdown";

export default defineConfig({
	entry: {
		index: "src/index.ts",
		client: "src/client.ts",
	},
	format: ["esm"],
	dts: true,
	clean: true,
	deps: {
		neverBundle: [
			"better-auth",
			"better-auth/client",
			"better-auth/api",
			"jose",
		],
	},
});
