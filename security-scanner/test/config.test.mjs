import test from "node:test";
import assert from "node:assert/strict";

import { validateConfig, DEFAULTS } from "../src/config.mjs";
import { resolveEngines, DEFAULT_ENGINES, runEngine } from "../src/engines.mjs";
import { mergeSarif } from "../src/upload.mjs";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

test("applies defaults and lets a repo override them", () => {
  const config = validateConfig({
    defaults: { issueThreshold: "medium" },
    repos: [{ name: "acme/api" }, { name: "acme/web", issueThreshold: "critical" }],
  });

  assert.equal(config.repos[0].issueThreshold, "medium");
  assert.equal(config.repos[1].issueThreshold, "critical");
  assert.deepEqual(config.repos[0].engines, DEFAULTS.engines);
});

test("accepts a bare string as a repo entry", () => {
  const config = validateConfig({ repos: ["acme/api"] });
  assert.equal(config.repos[0].name, "acme/api");
});

test("rejects malformed repo names rather than scanning the wrong thing", () => {
  assert.throws(() => validateConfig({ repos: [{ name: "no-slash" }] }), /owner\/repo/);
  assert.throws(() => validateConfig({ repos: [{ name: "a/b/c" }] }), /owner\/repo/);
  assert.throws(() => validateConfig({ repos: [{}] }), /owner\/repo/);
});

test("rejects an empty or missing repo list", () => {
  assert.throws(() => validateConfig({ repos: [] }), /non-empty/);
  assert.throws(() => validateConfig({}), /non-empty/);
});

test("rejects duplicate repos", () => {
  assert.throws(
    () => validateConfig({ repos: ["acme/api", "acme/api"] }),
    /Duplicate repo/
  );
});

test("engine overrides merge into defaults without dropping other fields", () => {
  const engines = resolveEngines({ trivy: { args: ["custom"] } });

  assert.deepEqual(engines.trivy.args, ["custom"]);
  assert.equal(engines.trivy.bin, DEFAULT_ENGINES.trivy.bin, "bin should survive an args override");
  assert.equal(engines["osv-scanner"].bin, "osv-scanner");
});

test("a wholly new engine can be declared in config", () => {
  const engines = resolveEngines({ "my-scanner": { bin: "x", args: [], output: "sarif" } });
  assert.equal(engines["my-scanner"].bin, "x");
});

test("a missing binary is reported, not thrown", async () => {
  const outDir = await mkdtemp(path.join(tmpdir(), "scan-"));
  const result = await runEngine(
    "ghost",
    { bin: "definitely-not-installed-xyz", args: [], output: "sarif" },
    { dir: process.cwd(), outDir }
  );

  assert.equal(result.ok, false);
  assert.match(result.error, /not installed or not on PATH/);
});

test("an engine writing to stdout is captured to a file", async () => {
  const outDir = await mkdtemp(path.join(tmpdir(), "scan-"));
  const result = await runEngine(
    "stdout-engine",
    {
      bin: process.execPath,
      args: ["-e", "process.stdout.write(JSON.stringify({runs:[]}))"],
      output: "sarif",
      stdout: true,
    },
    { dir: process.cwd(), outDir }
  );

  assert.equal(result.ok, true);
  assert.equal(await readFile(result.outputPath, "utf8"), '{"runs":[]}');
});

test("a non-zero exit still counts as success when output was produced", async () => {
  const outDir = await mkdtemp(path.join(tmpdir(), "scan-"));
  // Scanners exit non-zero to mean "findings present", which is not an error.
  const result = await runEngine(
    "noisy",
    {
      bin: process.execPath,
      args: ["-e", "process.stdout.write('{\"runs\":[]}'); process.exit(3)"],
      output: "sarif",
      stdout: true,
    },
    { dir: process.cwd(), outDir }
  );

  assert.equal(result.ok, true);
});

test("merging SARIF keeps one run per engine", () => {
  const merged = mergeSarif([
    { runs: [{ tool: { driver: { name: "a" } } }] },
    { runs: [{ tool: { driver: { name: "b" } } }] },
    {},
  ]);

  assert.equal(merged.runs.length, 2);
  assert.equal(merged.version, "2.1.0");
});
