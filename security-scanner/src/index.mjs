#!/usr/bin/env node
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { loadConfig } from "./config.mjs";
import { resolveEngines, runEngine } from "./engines.mjs";
import { findingsFromSarif } from "./sarif.mjs";
import { scanSbomForMalware } from "./malware.mjs";
import { createClient, syncIssues } from "./issues.mjs";
import { mergeSarif, uploadSarif } from "./upload.mjs";
import { meetsThreshold, severityRank, SEVERITIES } from "./severity.mjs";

const USAGE = `Usage: security-scanner <command> [options]

Commands:
  run       Scan a checkout and sync findings to GitHub issues
  scan      Scan a checkout and write findings.json (no GitHub calls)
  list      Print the configured repos as a JSON matrix for CI

Options:
  --config <path>   Config file (default: config/repos.json)
  --repo <o/n>      Repository being scanned (must exist in config)
  --dir <path>      Checkout to scan (default: .)
  --out <path>      Output directory (default: .scan-out)
  --dry-run         Plan issue changes without writing to GitHub
  --fail-on <sev>   Exit non-zero when a finding at or above <sev> is found
  --token <token>   GitHub token (default: GITHUB_TOKEN env var)
`;

/** @param {string[]} argv */
export function parseArgs(argv) {
  const options = { _: [] };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      options._.push(arg);
      continue;
    }

    const key = arg.slice(2);
    // Boolean flags take no value; everything else consumes the next token.
    if (key === "dry-run" || key === "help") {
      options[key] = true;
      continue;
    }

    options[key] = argv[i + 1];
    i += 1;
  }

  return options;
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

/**
 * Runs every enabled engine and normalizes their output into one finding list.
 *
 * @returns {Promise<{findings: object[], succeeded: Set<string>, failures: object[], sarifDocs: object[]}>}
 */
export async function scanCheckout(repoConfig, engines, context) {
  const findings = [];
  const succeeded = new Set();
  const failures = [];
  const sarifDocs = [];
  let sbomPath = null;

  for (const name of repoConfig.engines) {
    const definition = engines[name];
    if (!definition) {
      failures.push({ engine: name, error: `Unknown engine "${name}"` });
      continue;
    }

    context.logger.log(`  running ${name}...`);
    const result = await runEngine(name, definition, context);

    if (!result.ok) {
      failures.push({ engine: name, error: result.error });
      context.logger.warn(`  ! ${name}: ${result.error}`);
      continue;
    }

    succeeded.add(name);

    if (result.output === "sbom") {
      sbomPath = result.outputPath;
      continue;
    }

    try {
      const document = await readJson(result.outputPath);
      sarifDocs.push(document);
      findings.push(
        ...findingsFromSarif(document, {
          repo: repoConfig.name,
          engine: name,
          baseDir: context.dir,
        })
      );
    } catch (error) {
      failures.push({ engine: name, error: `Unreadable SARIF: ${error.message}` });
    }
  }

  if (repoConfig.malware) {
    if (!sbomPath) {
      failures.push({
        engine: "aikido-malware-feed",
        error: "Skipped: needs an SBOM, so the syft engine must be enabled",
      });
    } else {
      try {
        const sbom = await readJson(sbomPath);
        const malware = await scanSbomForMalware(sbom, repoConfig.name, {
          baseUrl: repoConfig.malwareFeedBaseUrl,
        });
        findings.push(...malware);
        succeeded.add("aikido-malware-feed");
      } catch (error) {
        failures.push({ engine: "aikido-malware-feed", error: error.message });
      }
    }
  }

  return { findings, succeeded, failures, sarifDocs };
}

/** Highest severity first, so a truncated read still shows the worst. */
function sortFindings(findings) {
  return [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
  }
  return counts;
}

async function commandScan(options, { logger = console } = {}) {
  const configPath = options.config ?? "config/repos.json";
  const { repos, engineOverrides } = await loadConfig(configPath);

  const repoName = options.repo;
  const repoConfig = repos.find((r) => r.name === repoName);
  if (!repoConfig) {
    throw new Error(
      `Repo "${repoName}" is not in ${configPath}. Configured: ${repos.map((r) => r.name).join(", ")}`
    );
  }

  const dir = path.resolve(options.dir ?? ".");
  const outDir = path.resolve(options.out ?? ".scan-out");
  await mkdir(outDir, { recursive: true });

  logger.log(`Scanning ${repoConfig.name} (${dir})`);

  const engines = resolveEngines(engineOverrides);
  const result = await scanCheckout(repoConfig, engines, { dir, outDir, logger });

  const findings = sortFindings(result.findings);
  const counts = summarize(findings);

  await writeFile(
    path.join(outDir, "findings.json"),
    JSON.stringify(
      {
        repo: repoConfig.name,
        scannedAt: new Date().toISOString(),
        counts,
        engines: {
          succeeded: [...result.succeeded],
          failed: result.failures,
        },
        findings,
      },
      null,
      2
    )
  );

  if (result.sarifDocs.length > 0) {
    await writeFile(
      path.join(outDir, "merged.sarif"),
      JSON.stringify(mergeSarif(result.sarifDocs), null, 2)
    );
  }

  logger.log(
    `Found ${findings.length}: ${counts.critical} critical, ${counts.high} high, ` +
      `${counts.medium} medium, ${counts.low} low, ${counts.info} info`
  );

  if (result.failures.length > 0) {
    logger.warn(`${result.failures.length} engine(s) did not complete - see findings.json`);
  }

  return { repoConfig, findings, counts, outDir, ...result };
}

async function commandRun(options, deps = {}) {
  const logger = deps.logger ?? console;
  const scan = await commandScan(options, { logger });

  const token = options.token ?? process.env.GITHUB_TOKEN;
  if (!token) {
    throw new Error("A GitHub token is required for `run` (use --token or GITHUB_TOKEN)");
  }

  const client = deps.client ?? createClient(token);

  const summary = await syncIssues(client, scan.repoConfig.name, scan.findings, {
    label: scan.repoConfig.label,
    issueThreshold: scan.repoConfig.issueThreshold,
    digestThreshold: scan.repoConfig.digestThreshold,
    strategy: scan.repoConfig.issueStrategy,
    succeededEngines: scan.succeeded,
    dryRun: Boolean(options["dry-run"]),
    logger,
  });

  logger.log(
    `Issues: ${summary.created} created, ${summary.updated} updated, ` +
      `${summary.closed} closed, ${summary.unchanged} unchanged`
  );

  if (scan.repoConfig.uploadSarif && !options["dry-run"]) {
    const sarifPath = path.join(scan.outDir, "merged.sarif");
    const commitSha = options["commit-sha"] ?? process.env.GITHUB_SHA;
    const ref = options.ref ?? `refs/heads/${scan.repoConfig.branch ?? "main"}`;

    if (!commitSha) {
      logger.warn("Skipping SARIF upload: no commit sha available");
    } else {
      try {
        await uploadSarif(client, scan.repoConfig.name, sarifPath, { commitSha, ref });
        logger.log("Uploaded SARIF to code scanning");
      } catch (error) {
        // Private repos without Advanced Security reject this; the issues are
        // already synced, so a failed upload must not fail the run.
        logger.warn(`SARIF upload failed (non-fatal): ${error.message}`);
      }
    }
  }

  return { scan, summary };
}

async function commandList(options, { logger = console } = {}) {
  const { repos } = await loadConfig(options.config ?? "config/repos.json");
  const matrix = repos.map((repo) => ({ repo: repo.name, branch: repo.branch }));
  logger.log(JSON.stringify({ include: matrix }));
  return matrix;
}

export async function main(argv) {
  const options = parseArgs(argv);
  const command = options._[0];

  if (options.help) {
    console.log(USAGE);
    return 0;
  }

  if (!command) {
    console.log(USAGE);
    return 1;
  }

  let findings = [];

  switch (command) {
    case "scan":
      ({ findings } = await commandScan(options));
      break;
    case "run":
      ({ scan: { findings } = {} } = await commandRun(options));
      break;
    case "list":
      await commandList(options);
      return 0;
    default:
      console.error(`Unknown command: ${command}\n`);
      console.log(USAGE);
      return 1;
  }

  // Exit code is a policy decision, so it is opt-in: a daily sweep wants to
  // record findings without failing, a pre-merge gate wants the opposite.
  if (options["fail-on"]) {
    // A typo here would otherwise become a gate that fails on everything, so
    // reject it outright rather than guessing what was meant.
    if (severityRank(options["fail-on"]) === -1) {
      console.error(
        `Unknown --fail-on severity "${options["fail-on"]}". Expected one of: ${SEVERITIES.join(", ")}`
      );
      return 1;
    }

    const breaching = findings.filter((f) => meetsThreshold(f.severity, options["fail-on"]));
    if (breaching.length > 0) {
      console.error(`Failing: ${breaching.length} finding(s) at or above ${options["fail-on"]}`);
      return 2;
    }
  }

  return 0;
}

// Only self-execute as a CLI; importing this module in tests must not run it.
if (process.argv[1] && process.argv[1].endsWith("index.mjs")) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((error) => {
      console.error(`security-scanner: ${error.message}`);
      process.exit(1);
    });
}
