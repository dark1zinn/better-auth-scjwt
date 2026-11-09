/**
 * Packs the package exactly as it would be published, installs the tarball
 * into a throwaway project outside the repository, and checks it as a real
 * consumer would: ESM runtime imports under Node.js and Bun, and TypeScript
 * inference under `bundler` and `NodeNext` resolution, including Better Auth's
 * session types and `@thallesp/nestjs-better-auth`'s `UserSession`.
 *
 * Usage: bun run test:package
 */
import { $ } from "bun";
import { cp, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const fixtures = join(root, "test/consumer");

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

const rootPackage = await readPackage(join(root, "package.json"));
const examplePackage = await readPackage(join(root, "examples/nestjs/package.json"));
const temp = await mkdtemp(join(tmpdir(), "scjwt-package-"));

try {
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
		(entry) =>
			!entry.startsWith("dist/") &&
			!["package.json", "README.md", "LICENSE"].includes(entry),
	);
	if (unexpected.length > 0) {
		throw new Error(`[check-package] unexpected files in tarball: ${unexpected.join(", ")}`);
	}
	for (const required of ["dist/index.mjs", "dist/index.d.mts", "dist/client.mjs", "dist/client.d.mts"]) {
		if (!listing.includes(required)) {
			throw new Error(`[check-package] tarball is missing ${required}`);
		}
	}

	const consumer = join(temp, "consumer");
	await cp(fixtures, consumer, { recursive: true });
	const dependencies: Record<string, string> = {
		"better-auth-scjwt": `file:${join(temp, tarball)}`,
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
	await writeFile(
		join(consumer, "package.json"),
		`${JSON.stringify({ name: "scjwt-packed-consumer", private: true, type: "module", dependencies }, null, 2)}\n`,
	);

	await $`bun install`.cwd(consumer).quiet();
	await $`node runtime.mjs`.cwd(consumer);
	await $`bun runtime.mjs`.cwd(consumer);
	for (const config of ["tsconfig.bundler.json", "tsconfig.nodenext.json"]) {
		await $`node node_modules/typescript/bin/tsc -p ${config}`.cwd(consumer);
		console.log(`packed consumer types ok (${config})`);
	}
	console.log(`[check-package] ${tarball}: ${listing.length} files verified`);
} finally {
	await rm(temp, { recursive: true, force: true });
}
