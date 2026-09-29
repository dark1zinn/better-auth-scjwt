import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

const root = join(import.meta.dir, "..");
const temporary = mkdtempSync(join(tmpdir(), "scjwt-git-install-"));
const source = join(temporary, "source");
const consumer = join(temporary, "consumer");
const env = {
  ...process.env,
  BUN_INSTALL_CACHE_DIR: join(temporary, "cache"),
  // bun run adds the checkout's binaries; the consumer must provide its own.
  PATH: (process.env.PATH ?? "").split(delimiter)
    .filter((entry) => !entry.includes("node_modules")).join(delimiter),
  NODE_PATH: "",
};

function run(command: string[], cwd: string): string {
  const result = Bun.spawnSync(command, { cwd, env, stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) {
    throw new Error(`${command.join(" ")} failed:\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout.toString();
}

try {
  mkdirSync(source);
  mkdirSync(consumer);
  // Include local edits, but never let prebuilt artifacts mask a broken prepare.
  const files = run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], root);
  for (const file of files.split("\0").filter(Boolean)) {
    if (file === "dist" || file.startsWith("dist/")) continue;
    const destination = join(source, file);
    mkdirSync(dirname(destination), { recursive: true });
    cpSync(join(root, file), destination);
  }
  run(["git", "init", "--quiet"], source);
  run(["git", "add", "."], source);
  run([
    "git", "-c", "user.name=Git install check", "-c", "user.email=check@example.invalid",
    "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Consumer install fixture",
  ], source);
  const revision = run(["git", "rev-parse", "HEAD"], source).trim();
  const manifest = await Bun.file(join(root, "package.json")).json();
  writeFileSync(join(consumer, "package.json"), JSON.stringify({
    name: "scjwt-git-install-consumer",
    private: true,
    type: "module",
    dependencies: {
      ...manifest.peerDependencies,
      "better-auth-scjwt": `git+${pathToFileURL(source).href}#${revision}`,
    },
    trustedDependencies: ["better-auth-scjwt"],
  }, null, 2));
  writeFileSync(join(consumer, "check.ts"), `
import { strict as assert } from "node:assert";
import { scjwt } from "better-auth-scjwt";
import { scjwtClient } from "better-auth-scjwt/client";
assert.equal(typeof scjwt, "function");
assert.equal(typeof scjwtClient, "function");
console.log("Both Git-installed package entrypoints resolve and import successfully.");
`);
  run([process.execPath, "install"], consumer);
  console.log(run([process.execPath, "run", "check.ts"], consumer).trim());
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
