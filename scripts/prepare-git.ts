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

const STRIPPED_ENV =
	/^npm_config_(production|omit|include|dev|only|optional|ignore_scripts|frozen_lockfile)$/i;

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

function childEnv(): Record<string, string> {
	const env: Record<string, string> = {};
	for (const [key, value] of Object.entries(process.env)) {
		if (value !== undefined && !STRIPPED_ENV.test(key)) {
			env[key] = value;
		}
	}
	env.NODE_ENV = "development";
	return env;
}

async function run(args: readonly string[], cwd: string): Promise<void> {
	const proc = Bun.spawn([process.execPath, ...args], {
		cwd,
		env: childEnv(),
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
		await run(INSTALL_ARGS, temp);
		await run(BUILD_ARGS, temp);

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

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error);
	console.error(`[prepare-git] ${message}`);
	process.exit(1);
});
