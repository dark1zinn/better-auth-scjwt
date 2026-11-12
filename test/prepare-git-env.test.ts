import { describe, expect, test } from "bun:test";
import { buildEnv, FORWARD_ENV_VARIABLE, installEnv } from "../scripts/prepare-git";

const CONSUMER_ENV = {
	PATH: "/usr/bin",
	HOME: "/home/consumer",
	TMPDIR: "/tmp",
	LANG: "en_US.UTF-8",
	LC_ALL: "C",
	BUN_INSTALL_CACHE_DIR: "/cache/bun",
	NODE_ENV: "production",
	// Secrets typically present in CI or a developer shell.
	SECRET_TOKEN: "ghp_example_not_real",
	GITHUB_TOKEN: "ghs_example",
	AWS_SECRET_ACCESS_KEY: "aws-example",
	SSH_AUTH_SOCK: "/run/ssh-agent.sock",
	NPM_CONFIG_TOKEN: "npm-registry-token",
	BUN_CONFIG_TOKEN: "bun-registry-token",
	NPM_TOKEN: "npmrc-referenced-token",
	// Install-scope flags the nested install must not inherit.
	npm_config_production: "true",
	npm_config_omit: "dev",
	// Network settings the nested install needs.
	NPM_CONFIG_REGISTRY: "https://registry.example.com/",
	HTTPS_PROXY: "http://proxy.example.com:3128",
	no_proxy: "localhost",
	SSL_CERT_FILE: "/etc/ssl/corp.pem",
	NPM_CONFIG_USERCONFIG: "/run/npmrc",
} satisfies Record<string, string>;

const SECRETS = [
	"SECRET_TOKEN",
	"GITHUB_TOKEN",
	"AWS_SECRET_ACCESS_KEY",
	"SSH_AUTH_SOCK",
	"NPM_CONFIG_TOKEN",
	"BUN_CONFIG_TOKEN",
	"NPM_TOKEN",
];

describe("prepare-git nested environments", () => {
	test("neither nested step sees consumer secrets or install-scope flags", () => {
		for (const env of [installEnv(CONSUMER_ENV), buildEnv(CONSUMER_ENV)]) {
			for (const name of [...SECRETS, "npm_config_production", "npm_config_omit"]) {
				expect(env).not.toHaveProperty(name);
			}
		}
	});

	test("both steps keep what locating and running the toolchain needs, in development mode", () => {
		for (const env of [installEnv(CONSUMER_ENV), buildEnv(CONSUMER_ENV)]) {
			expect(env).toMatchObject({
				PATH: "/usr/bin",
				HOME: "/home/consumer",
				TMPDIR: "/tmp",
				LANG: "en_US.UTF-8",
				LC_ALL: "C",
				BUN_INSTALL_CACHE_DIR: "/cache/bun",
				NODE_ENV: "development",
			});
		}
	});

	test("only the install step gets registry, proxy, and CA settings", () => {
		const network = {
			NPM_CONFIG_REGISTRY: "https://registry.example.com/",
			HTTPS_PROXY: "http://proxy.example.com:3128",
			no_proxy: "localhost",
			SSL_CERT_FILE: "/etc/ssl/corp.pem",
			NPM_CONFIG_USERCONFIG: "/run/npmrc",
		};
		expect(installEnv(CONSUMER_ENV)).toMatchObject(network);
		const build = buildEnv(CONSUMER_ENV);
		for (const name of Object.keys(network)) {
			expect(build).not.toHaveProperty(name);
		}
	});

	test("explicitly forwarded variables reach the install step only", () => {
		const source = { ...CONSUMER_ENV, [FORWARD_ENV_VARIABLE]: " NPM_TOKEN , ,MISSING_VAR" };
		const install = installEnv(source);
		expect(install.NPM_TOKEN).toBe("npmrc-referenced-token");
		expect(install).not.toHaveProperty("MISSING_VAR");
		// Forwarding one name does not open the door to the others.
		expect(install).not.toHaveProperty("NPM_CONFIG_TOKEN");
		expect(install).not.toHaveProperty("SECRET_TOKEN");
		expect(buildEnv(source)).not.toHaveProperty("NPM_TOKEN");
	});
});
