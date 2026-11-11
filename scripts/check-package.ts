/**
 * Checks the package the way a real consumer receives it.
 *
 * Default (packed): packs the package exactly as it would be published, installs
 * the tarball into a throwaway project outside the repository, and checks it:
 * ESM runtime imports under Node.js and Bun, and TypeScript inference under
 * `bundler` and `NodeNext` resolution, including Better Auth's session types and
 * `@thallesp/nestjs-better-auth`'s `UserSession`.
 *
 * `--dependency <specifier>` (for example `github:owner/repo#<sha>`): installs the
 * given specifier instead of packing, so Bun runs this package's `prepare` build.
 * It runs the same consumer checks, plus a production-filtered workspace that
 * must import without build tools.
 *
 * Usage: bun run test:package
 *        bun run test:git --dependency <specifier>
 */
import { $ } from "bun";
import { access, cp, mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const fixtures = join(root, "test/consumer");

const ENTRYPOINTS = ["dist/index.mjs", "dist/index.d.mts", "dist/client.mjs", "dist/client.d.mts"];

// Files the packed tarball may contain outside `dist/`.
const TARBALL_EXTRA_FILES = ["package.json", "README.md", "LICENSE", "scripts/prepare-git.ts"];

const TYPE_CONFIGS = ["tsconfig.bundler.json", "tsconfig.nodenext.json"];

const IMPORT_CHECK = `(async () => {
	const server = await import("better-auth-scjwt");
	const client = await import("better-auth-scjwt/client");
	if (typeof server.scjwt !== "function" || typeof client.scjwtClient !== "function") {
		throw new Error("[check-package] scjwt or scjwtClient is not a function");
	}
	console.log("[check-package] runtime imports ok");
})();`;

interface PackageJson {
	dependencies?: Record<string, string>;
	devDependencies?: Record<string, string>;
}

async function readPackage(path: string): Promise<PackageJson> {
	return (await Bun.file(path).json()) as PackageJson;
}

function version(pkg: PackageJson, name: string): string {
	const found = pkg.dependencies?.[name] ?? pkg.devDependencies?.[name];
	if (!found) {
		throw new Error(`[check-package] no version for ${name}`);
	}
	return found;
}

async function exists(path: string): Promise<boolean> {
	try {
		await access(path);
		return true;
	} catch {
		return false;
	}
}

function parseDependency(argv: string[]): string | undefined {
	let dependency: string | undefined;
	for (let index = 0; index < argv.length; index++) {
		const arg = argv[index];
		if (arg !== "--dependency") {
			throw new Error(`[check-package] unknown argument: ${arg}`);
		}
		const value = argv[index + 1];
		if (value === undefined || value.length === 0 || value.startsWith("--")) {
			throw new Error("[check-package] --dependency requires a specifier");
		}
		dependency = value;
		index++;
	}
	return dependency;
}

const rootPackage = await readPackage(join(root, "package.json"));
const examplePackage = await readPackage(join(root, "examples/nestjs/package.json"));

// Versions shared by every consumer, taken from the repository so they match the tested set.
function sharedDependencies(scjwtSpecifier: string): Record<string, string> {
	const dependencies: Record<string, string> = {
		"better-auth-scjwt": scjwtSpecifier,
		"better-auth": version(rootPackage, "better-auth"),
		"@better-auth/core": version(rootPackage, "@better-auth/core"),
		jose: version(rootPackage, "jose"),
		// Better Auth's own declarations reference `bun:sqlite`; checking them with skipLibCheck off
		// needs Bun's types, which also bring the `@types/node` release they are written against.
		"@types/bun": version(rootPackage, "@types/bun"),
	};
	for (const name of [
		"@thallesp/nestjs-better-auth",
		"@nestjs/common",
		"@nestjs/core",
		"@nestjs/platform-express",
		"reflect-metadata",
		"rxjs",
		"@types/express",
		"typescript",
	]) {
		dependencies[name] = version(examplePackage, name);
	}
	return dependencies;
}

async function createConsumer(
	dir: string,
	name: string,
	dependencies: Record<string, string>,
	trusted: boolean,
): Promise<void> {
	await cp(fixtures, dir, { recursive: true });
	const manifest: Record<string, unknown> = { name, private: true, type: "module", dependencies };
	if (trusted) {
		manifest.trustedDependencies = ["better-auth-scjwt"];
	}
	await writeFile(join(dir, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

async function checkConsumer(consumer: string, label: string): Promise<void> {
	await $`node runtime.mjs`.cwd(consumer);
	await $`bun runtime.mjs`.cwd(consumer);
	for (const config of TYPE_CONFIGS) {
		await $`node node_modules/typescript/bin/tsc -p ${config}`.cwd(consumer);
		console.log(`${label} types ok (${config})`);
	}
}

function installEnv(cache: string): Record<string, string> {
	const env: Record<string, string> = {};
	for (const [key, value] of Object.entries(process.env)) {
		if (value !== undefined) {
			env[key] = value;
		}
	}
	env.BUN_INSTALL_CACHE_DIR = cache;
	return env;
}

async function checkPacked(temp: string): Promise<void> {
	// `prepack` runs the build, so the tarball is produced by the same lifecycle as a publish.
	await $`bun pm pack --quiet --destination ${temp}`.cwd(root);
	const tarball = (await readdir(temp)).find((name) => name.endsWith(".tgz"));
	if (!tarball) {
		throw new Error("[check-package] bun pm pack produced no tarball");
	}

	const listing = (await $`tar -tzf ${join(temp, tarball)}`.text())
		.split("\n")
		.filter(Boolean)
		.map((entry) => entry.replace(/^package\//, ""));
	const unexpected = listing.filter(
		(entry) => !entry.startsWith("dist/") && !TARBALL_EXTRA_FILES.includes(entry),
	);
	if (unexpected.length > 0) {
		throw new Error(`[check-package] unexpected files in tarball: ${unexpected.join(", ")}`);
	}
	for (const required of ENTRYPOINTS) {
		if (!listing.includes(required)) {
			throw new Error(`[check-package] tarball is missing ${required}`);
		}
	}

	const consumer = join(temp, "consumer");
	await createConsumer(
		consumer,
		"scjwt-packed-consumer",
		sharedDependencies(`file:${join(temp, tarball)}`),
		false,
	);
	await $`bun install`.cwd(consumer).quiet();
	await checkConsumer(consumer, "packed consumer");
	console.log(`[check-package] ${tarball}: ${listing.length} files verified`);
}

async function checkGitDependency(specifier: string, temp: string): Promise<void> {
	const sentinel = join(temp, "outside-sentinel.txt");
	await writeFile(sentinel, "caller-owned\n");

	// Full consumer: Bun builds the dependency through its trusted `prepare` script.
	const consumer = join(temp, "consumer");
	const consumerCache = await mkdtemp(join(temp, "cache-"));
	await createConsumer(consumer, "scjwt-git-consumer", sharedDependencies(specifier), true);
	await $`bun install`.cwd(consumer).env(installEnv(consumerCache)).quiet();
	for (const entry of ENTRYPOINTS) {
		if (!(await exists(join(consumer, "node_modules/better-auth-scjwt", entry)))) {
			throw new Error(`[check-package] git install is missing ${entry}`);
		}
	}
	console.log("[check-package] git dependency built dist during install");
	await checkConsumer(consumer, "git consumer");

	// Production-filtered workspace: lock with a full install, then install from the lock alone.
	const workspace = join(temp, "workspace-a");
	const workspaceCache = await mkdtemp(join(temp, "cache-"));
	await mkdir(join(workspace, "server"), { recursive: true });
	await writeFile(
		join(workspace, "package.json"),
		`${JSON.stringify(
			{
				name: "scjwt-git-workspace",
				private: true,
				workspaces: ["server"],
				trustedDependencies: ["better-auth-scjwt"],
			},
			null,
			2,
		)}\n`,
	);
	// The production server carries only SCJWT and its runtime peers, not the NestJS example stack.
	const serverDependencies: Record<string, string> = {
		"better-auth-scjwt": specifier,
		"better-auth": version(rootPackage, "better-auth"),
		"@better-auth/core": version(rootPackage, "@better-auth/core"),
		jose: version(rootPackage, "jose"),
	};
	await writeFile(
		join(workspace, "server/package.json"),
		`${JSON.stringify(
			{ name: "server", private: true, type: "module", dependencies: serverDependencies },
			null,
			2,
		)}\n`,
	);
	await $`bun install`.cwd(workspace).env(installEnv(workspaceCache)).quiet();

	const production = join(temp, "workspace-b");
	const productionCache = await mkdtemp(join(temp, "cache-"));
	await mkdir(join(production, "server"), { recursive: true });
	await cp(join(workspace, "package.json"), join(production, "package.json"));
	await cp(join(workspace, "server/package.json"), join(production, "server/package.json"));
	await cp(join(workspace, "bun.lock"), join(production, "bun.lock"));
	await $`bun install --frozen-lockfile --production --filter server`
		.cwd(production)
		.env(installEnv(productionCache))
		.quiet();

	const server = join(production, "server");
	await $`bun -e ${IMPORT_CHECK}`.cwd(server);
	await $`node --input-type=module -e ${IMPORT_CHECK}`.cwd(server);
	for (const devOnly of ["typescript", "tsdown"]) {
		if (await exists(join(production, "node_modules", devOnly))) {
			throw new Error(`[check-package] production install contains ${devOnly}`);
		}
	}
	console.log("[check-package] production-filtered workspace imports ok");

	if (!(await exists(sentinel))) {
		throw new Error("[check-package] caller-owned sentinel was removed during installs");
	}
	console.log(`[check-package] git dependency ${specifier} verified`);
}

const dependency = parseDependency(process.argv.slice(2));
const temp = await mkdtemp(join(tmpdir(), "scjwt-package-"));

try {
	if (dependency === undefined) {
		await checkPacked(temp);
	} else {
		await checkGitDependency(dependency, temp);
	}
} finally {
	await rm(temp, { recursive: true, force: true });
}
