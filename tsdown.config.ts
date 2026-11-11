import { defineConfig } from "tsdown";

export default defineConfig({
	entry: {
		index: "src/index.ts",
		client: "src/client.ts",
	},
	format: ["esm"],
	// One declaration pipeline: TypeScript 7 (tsgo) emits declarations and
	// rolldown-plugin-dts bundles index/client .d.mts with explicit extensions.
	// scripts/check-package.ts verifies the packed result under bundler and NodeNext.
	dts: { generator: "tsgo" },
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
