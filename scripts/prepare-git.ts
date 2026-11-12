/**
 * Runs as `prepare` when this package is installed from a Git checkout, where
 * `dist/` is not committed. Bun runs `prepare` without first installing the
 * package's devDependencies, so the build happens in a disposable copy of the
 * source tree that installs its own dependencies with `--ignore-scripts`
 * (which also prevents recursion into this script).
 *
 * In a packed tarball `src/` is absent and `dist/` must already be present.
 * The built entrypoints replace only this package's own `dist/`.
 */
import { access, copyFile, cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const pkgRoot = resolve(import.meta.dir, "..");

const ENTRYPOINTS = [
	"dist/index.mjs",
	"dist/index.d.mts",
	"dist/client.mjs",
	"dist/client.d.mts",
] as const;

// The filter flag lives here so the install scope can be changed in one place.
const INSTALL_ARGS = [
	"install",
	"--frozen-lockfile",
	"--ignore-scripts",
	"--filter",
	"better-auth-scjwt",
] as const;

const BUILD_ARGS = ["run", "build"] as const;

// Only what the build needs. The example manifest keeps the workspace graph and lockfile valid.
const SOURCE_FILES = [
	"package.json",
	"bun.lock",
	"tsconfig.json",
	"tsdown.config.ts",
	"examples/nestjs/package.json",
] as const;

const SOURCE_DIR = "src";

const EXCLUDED_NAME = /^(node_modules|\.git|\.env(\..*)?)$/;

/**
 * Variables both nested steps get: locating tools, temp and cache dirs, locale,
 * and output formatting. Everything else in the consumer's install environment
 * (CI tokens, cloud credentials, `SSH_AUTH_SOCK`, …) is withheld, because the
 * build runs this repository's toolchain, resolved from this repository's lockfile.
 */
const BASE_ENV = [
	/^PATH$/i,
	/^PATHEXT$/i,
	/^HOME$/i,
	/^USERPROFILE$/i,
	/^(TMPDIR|TEMP|TMP)$/i,
	/^(SYSTEMROOT|WINDIR|COMSPEC)$/i,
	/^LANG$/,
	/^LC_[A-Z]+$/,
	/^(NO_COLOR|FORCE_COLOR)$/,
	/^BUN_INSTALL(_[A-Z_]+)?$/,
	/^BUN_RUNTIME_TRANSPILER_CACHE_PATH$/,
] as const;

/**
 * Extra variables the nested install needs to fetch the toolchain: registry
 * location, proxies, CA bundles, and where `.npmrc` lives. Registry tokens are
 * deliberately absent; see {@link FORWARD_ENV_VARIABLE}.
 */
const INSTALL_ENV = [
	/^(NPM|BUN)_CONFIG_REGISTRY$/i,
	/^(HTTP_PROXY|HTTPS_PROXY|NO_PROXY)$/i,
	/^(SSL_CERT_FILE|SSL_CERT_DIR|NODE_EXTRA_CA_CERTS|NODE_USE_SYSTEM_CA)$/,
	/^NPM_CONFIG_(CAFILE|USERCONFIG)$/i,
	/^XDG_CONFIG_HOME$/,
	/^BUN_CONFIG_MAX_HTTP_REQUESTS$/,
] as const;

/**
 * Comma-separated variable names the consumer explicitly forwards to the
 * nested install, for example a registry token referenced from `.npmrc`. They
 * never reach the build step.
 */
export const FORWARD_ENV_VARIABLE = "SCJWT_PREPARE_FORWARD_ENV";

async function exists(path: string): Promise<boolean> {
	try {
		await access(path);
		return true;
	} catch {
		return false;
	}
}

async function missingEntrypoints(root: string): Promise<string[]> {
	const missing: string[] = [];
	for (const entry of ENTRYPOINTS) {
		if (!(await exists(join(root, entry)))) {
			missing.push(entry);
		}
	}
	return missing;
}

function allowlisted(
	source: Record<string, string | undefined>,
	patterns: readonly RegExp[],
	extraNames: ReadonlySet<string> = new Set(),
): Record<string, string> {
	const env: Record<string, string> = {};
	for (const [key, value] of Object.entries(source)) {
		if (value !== undefined && (extraNames.has(key) || patterns.some((pattern) => pattern.test(key)))) {
			env[key] = value;
		}
	}
	env.NODE_ENV = "development";
	return env;
}

/** Environment for the nested `bun install`: base, network settings, and explicit opt-ins. */
export function installEnv(source: Record<string, string | undefined>): Record<string, string> {
	const forwarded = new Set(
		(source[FORWARD_ENV_VARIABLE] ?? "")
			.split(",")
			.map((name) => name.trim())
			.filter(Boolean),
	);
	return allowlisted(source, [...BASE_ENV, ...INSTALL_ENV], forwarded);
}

/** Environment for the nested `bun run build`: the base allowlist only, no network or credentials. */
export function buildEnv(source: Record<string, string | undefined>): Record<string, string> {
	return allowlisted(source, BASE_ENV);
}

async function run(
	args: readonly string[],
	cwd: string,
	env: Record<string, string>,
): Promise<void> {
	const proc = Bun.spawn([process.execPath, ...args], {
		cwd,
		env,
		stdin: "ignore",
		stdout: "inherit",
		stderr: "inherit",
	});
	const code = await proc.exited;
	if (code !== 0) {
		throw new Error(`bun ${args.join(" ")} failed in ${cwd} with exit code ${code}`);
	}
}

async function stageSource(temp: string): Promise<void> {
	for (const file of SOURCE_FILES) {
		const target = join(temp, file);
		await mkdir(dirname(target), { recursive: true });
		await copyFile(join(pkgRoot, file), target);
	}
	await cp(join(pkgRoot, SOURCE_DIR), join(temp, SOURCE_DIR), {
		recursive: true,
		filter: (source) => !EXCLUDED_NAME.test(basename(source)),
	});
}

async function main(): Promise<void> {
	if (!(await exists(join(pkgRoot, "src/index.ts")))) {
		// Packed tarball or already-built checkout: nothing to build, only verify the artifacts.
		const missing = await missingEntrypoints(pkgRoot);
		if (missing.length > 0) {
			throw new Error(`package has no src/ and is missing built output: ${missing.join(", ")}`);
		}
		return;
	}

	const temp = await mkdtemp(join(tmpdir(), "better-auth-scjwt-build-"));
	try {
		await stageSource(temp);
		await run(INSTALL_ARGS, temp, installEnv(process.env));
		await run(BUILD_ARGS, temp, buildEnv(process.env));

		const missing = await missingEntrypoints(temp);
		if (missing.length > 0) {
			throw new Error(`isolated build did not produce: ${missing.join(", ")}`);
		}

		await rm(join(pkgRoot, "dist"), { recursive: true, force: true });
		await cp(join(temp, "dist"), join(pkgRoot, "dist"), { recursive: true });
	} finally {
		await rm(temp, { recursive: true, force: true });
	}
}

if (import.meta.main) {
	main().catch((error: unknown) => {
		const message = error instanceof Error ? error.message : String(error);
		console.error(`[prepare-git] ${message}`);
		process.exit(1);
	});
}
