import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const CLI = path.resolve(import.meta.dirname, "../src/index.mjs");

/**
 * Builds a throwaway workspace with a config whose engines are stub commands,
 * so the pipeline is exercised end to end without installing real scanners.
 */
async function workspace({ engineScript, malware = false }) {
  const dir = await mkdtemp(path.join(tmpdir(), "scanner-it-"));
  await mkdir(path.join(dir, "config"), { recursive: true });

  const config = {
    defaults: {
      engines: ["stub"],
      issueThreshold: "high",
      malware,
    },
    engineOverrides: {
      stub: {
        bin: process.execPath,
        args: ["-e", engineScript, "{out}"],
        output: "sarif",
      },
    },
    repos: [{ name: "acme/api", branch: "main" }],
  };

  await writeFile(path.join(dir, "config", "repos.json"), JSON.stringify(config));
  return dir;
}

const WRITE_SARIF = `
const fs = require("fs");
fs.writeFileSync(process.argv[1], JSON.stringify({
  version: "2.1.0",
  runs: [{
    tool: { driver: { name: "stub", rules: [
      { id: "CVE-100", shortDescription: { text: "Critical dep flaw" },
        properties: { "security-severity": "9.5" } },
      { id: "LINT-1", shortDescription: { text: "Minor style issue" },
        properties: { "security-severity": "2.0" } }
    ] } },
    results: [
      { ruleId: "CVE-100", message: { text: "bad" },
        properties: { package_name: "lodash", package_version: "4.17.20", fixed_version: "4.17.21" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "package-lock.json" },
          region: { startLine: 12 } } }] },
      { ruleId: "LINT-1", message: { text: "meh" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "src/a.js" } } }] }
    ]
  }]
}));
`;

test("scan produces normalized findings.json and merged SARIF", async () => {
  const dir = await workspace({ engineScript: WRITE_SARIF });

  const { stdout } = await run(process.execPath, [
    CLI, "scan",
    "--config", path.join(dir, "config", "repos.json"),
    "--repo", "acme/api",
    "--dir", dir,
    "--out", path.join(dir, "out"),
  ]);

  assert.match(stdout, /1 critical/);

  const report = JSON.parse(await readFile(path.join(dir, "out", "findings.json"), "utf8"));
  assert.equal(report.repo, "acme/api");
  assert.equal(report.findings.length, 2);
  assert.deepEqual(report.engines.succeeded, ["stub"]);

  // Sorted worst-first.
  assert.equal(report.findings[0].severity, "critical");
  assert.equal(report.findings[0].package, "lodash");
  assert.equal(report.findings[0].fixedVersion, "4.17.21");
  assert.ok(report.findings[0].fingerprint);

  const merged = JSON.parse(await readFile(path.join(dir, "out", "merged.sarif"), "utf8"));
  assert.equal(merged.runs.length, 1);
});

test("a failing engine is recorded but does not abort the scan", async () => {
  const dir = await workspace({ engineScript: "process.exit(1)" });

  const { stdout } = await run(process.execPath, [
    CLI, "scan",
    "--config", path.join(dir, "config", "repos.json"),
    "--repo", "acme/api",
    "--dir", dir,
    "--out", path.join(dir, "out"),
  ]);

  assert.match(stdout, /Found 0/);

  const report = JSON.parse(await readFile(path.join(dir, "out", "findings.json"), "utf8"));
  assert.equal(report.engines.failed.length, 1);
  assert.equal(report.engines.failed[0].engine, "stub");
  assert.deepEqual(report.engines.succeeded, []);
});

test("the malware check is skipped with an explanation when no SBOM exists", async () => {
  const dir = await workspace({ engineScript: WRITE_SARIF, malware: true });

  await run(process.execPath, [
    CLI, "scan",
    "--config", path.join(dir, "config", "repos.json"),
    "--repo", "acme/api",
    "--dir", dir,
    "--out", path.join(dir, "out"),
  ]);

  const report = JSON.parse(await readFile(path.join(dir, "out", "findings.json"), "utf8"));
  const skipped = report.engines.failed.find((f) => f.engine === "aikido-malware-feed");
  assert.match(skipped.error, /syft engine must be enabled/);
});

test("--fail-on exits 2 when a breaching finding is present", async () => {
  const dir = await workspace({ engineScript: WRITE_SARIF });

  await assert.rejects(
    () =>
      run(process.execPath, [
        CLI, "scan",
        "--config", path.join(dir, "config", "repos.json"),
        "--repo", "acme/api",
        "--dir", dir,
        "--out", path.join(dir, "out"),
        "--fail-on", "critical",
      ]),
    (error) => {
      assert.equal(error.code, 2);
      return true;
    }
  );
});

test("an unknown --fail-on severity is a hard config error, not a blanket fail", async () => {
  const dir = await workspace({ engineScript: WRITE_SARIF });

  // A typo in a gate must not quietly become "fail on everything".
  await assert.rejects(
    () =>
      run(process.execPath, [
        CLI, "scan",
        "--config", path.join(dir, "config", "repos.json"),
        "--repo", "acme/api",
        "--dir", dir,
        "--out", path.join(dir, "out"),
        "--fail-on", "sevear",
      ]),
    (error) => {
      assert.equal(error.code, 1, "config errors exit 1, breached gates exit 2");
      assert.match(error.stderr, /Unknown --fail-on severity "sevear"/);
      assert.match(error.stderr, /critical/);
      return true;
    }
  );
});

test("--fail-on exits 0 when no finding breaches the gate", async () => {
  // No findings at all, so even the strictest gate must pass.
  const dir = await workspace({ engineScript: 'require("fs").writeFileSync(process.argv[1], JSON.stringify({version:"2.1.0",runs:[{tool:{driver:{name:"stub"}},results:[]}]}))' });

  const result = await run(process.execPath, [
    CLI, "scan",
    "--config", path.join(dir, "config", "repos.json"),
    "--repo", "acme/api",
    "--dir", dir,
    "--out", path.join(dir, "out"),
    "--fail-on", "low",
  ]);

  assert.match(result.stdout, /Found 0/);
});

test("an unconfigured repo fails with the list of configured ones", async () => {
  const dir = await workspace({ engineScript: WRITE_SARIF });

  await assert.rejects(
    () =>
      run(process.execPath, [
        CLI, "scan",
        "--config", path.join(dir, "config", "repos.json"),
        "--repo", "acme/not-configured",
        "--dir", dir,
      ]),
    /is not in .*Configured: acme\/api/s
  );
});
