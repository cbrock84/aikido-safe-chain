import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

/**
 * Engine registry.
 *
 * Engines are declarative on purpose: adding one is a config entry, not code.
 * The argv templates are defaults, not gospel - these CLIs change their flags
 * between majors, so every command here can be overridden per-engine in
 * repos.json without touching this file.
 *
 * "{dir}" is the checkout being scanned, "{out}" the file to write.
 */
export const DEFAULT_ENGINES = {
  "osv-scanner": {
    bin: "osv-scanner",
    args: ["scan", "source", "--recursive", "--format", "sarif", "--output", "{out}", "{dir}"],
    output: "sarif",
    // 128 is "no package sources found" - a clean no-op on a repo with no
    // manifests, not a failure. Without this the engine would be marked failed,
    // and since a failed engine is never allowed to close issues, a repo that
    // removed its last lockfile would keep stale issues open forever.
    noFindingsExitCodes: [128],
    description: "Dependency vulnerabilities from osv.dev",
  },
  trivy: {
    bin: "trivy",
    args: [
      "fs", "--scanners", "vuln,misconfig,secret",
      "--format", "sarif", "--output", "{out}", "{dir}",
    ],
    output: "sarif",
    description: "Vulnerabilities, IaC misconfiguration and secrets",
  },
  gitleaks: {
    bin: "gitleaks",
    args: ["dir", "{dir}", "--report-format", "sarif", "--report-path", "{out}", "--exit-code", "0"],
    output: "sarif",
    description: "Hardcoded secrets",
  },
  zizmor: {
    bin: "zizmor",
    args: ["--format", "sarif", "{dir}"],
    output: "sarif",
    stdout: true,
    // Several zizmor audits query the GitHub API (e.g. ref-confusion resolves
    // an action's branches). Without GH_TOKEN it aborts with 401 rather than
    // degrading, so the workflow passes a token. For local runs without one,
    // add "--offline" via engineOverrides to skip the online audits.
    description: "GitHub Actions workflow security (needs GH_TOKEN for online audits)",
  },
  syft: {
    bin: "syft",
    args: ["scan", "dir:{dir}", "-o", "cyclonedx-json={out}"],
    output: "sbom",
    description: "CycloneDX SBOM, also feeds the malware check",
  },
  checkov: {
    bin: "checkov",
    args: ["-d", "{dir}", "-o", "sarif", "--output-file-path", "{outdir}", "--soft-fail"],
    output: "sarif",
    // Checkov names its own output file rather than honouring a path.
    outputFile: "results.sarif",
    description: "Infrastructure-as-code misconfiguration",
  },
  opengrep: {
    bin: "opengrep",
    args: ["scan", "--sarif", "--sarif-output", "{out}", "--config", "auto", "{dir}"],
    output: "sarif",
    description: "Static analysis (SAST)",
  },
};

/**
 * Scanners exit non-zero to signal "findings were present", which is the normal
 * case, not an error. We judge success by whether usable output landed, and
 * only surface the exit code when it did not.
 */
async function execute(bin, args, { cwd, captureStdout }) {
  return new Promise((resolve) => {
    const child = spawn(bin, args, {
      cwd,
      stdio: ["ignore", captureStdout ? "pipe" : "inherit", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    if (captureStdout) {
      child.stdout.on("data", (chunk) => (stdout += chunk));
    }
    child.stderr.on("data", (chunk) => (stderr += chunk));

    child.on("error", (error) => {
      resolve({ code: null, stdout, stderr, spawnError: error });
    });

    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

/**
 * Runs one engine against one checkout.
 *
 * A missing binary or a crashed scanner degrades that engine only - the rest of
 * the scan continues. Silently dropping an engine would be worse than a noisy
 * scan, so the failure is returned and reported rather than swallowed.
 *
 * @param {string} name
 * @param {object} definition
 * @param {{dir: string, outDir: string}} context
 * @returns {Promise<{name: string, ok: boolean, outputPath?: string, output?: string, error?: string}>}
 */
export async function runEngine(name, definition, context) {
  await mkdir(context.outDir, { recursive: true });

  const extension = definition.output === "sbom" ? "cdx.json" : "sarif";
  const outputPath = definition.outputFile
    ? path.join(context.outDir, definition.outputFile)
    : path.join(context.outDir, `${name}.${extension}`);

  const args = definition.args.map((arg) =>
    arg
      .replaceAll("{dir}", context.dir)
      .replaceAll("{out}", outputPath)
      .replaceAll("{outdir}", context.outDir)
  );

  const result = await execute(definition.bin, args, {
    cwd: context.dir,
    captureStdout: Boolean(definition.stdout),
  });

  if (result.spawnError) {
    const missing = result.spawnError.code === "ENOENT";
    return {
      name,
      ok: false,
      error: missing
        ? `${definition.bin} is not installed or not on PATH`
        : `${definition.bin} failed to start: ${result.spawnError.message}`,
    };
  }

  if (definition.stdout) {
    if (!result.stdout.trim()) {
      if ((definition.noFindingsExitCodes ?? []).includes(result.code)) {
        await writeFile(outputPath, JSON.stringify(EMPTY_SARIF));
        return { name, ok: true, outputPath, output: definition.output, empty: true };
      }

      return { name, ok: false, error: describeEmpty(name, result) };
    }
    await writeFile(outputPath, result.stdout);
    return { name, ok: true, outputPath, output: definition.output };
  }

  try {
    await readFile(outputPath);
  } catch {
    // Some engines write nothing at all when there is nothing to scan. That is
    // a successful empty result, so synthesize one rather than reporting a
    // failure - downstream code then sees a normal zero-finding run.
    if ((definition.noFindingsExitCodes ?? []).includes(result.code)) {
      await writeFile(outputPath, JSON.stringify(EMPTY_SARIF));
      return { name, ok: true, outputPath, output: definition.output, empty: true };
    }

    return { name, ok: false, error: describeEmpty(name, result) };
  }

  return { name, ok: true, outputPath, output: definition.output };
}

/** A valid SARIF document reporting nothing, used for clean empty results. */
const EMPTY_SARIF = {
  version: "2.1.0",
  runs: [{ tool: { driver: { name: "security-scanner" } }, results: [] }],
};

function describeEmpty(name, result) {
  const detail = result.stderr.trim().split("\n").slice(-3).join(" ").slice(0, 300);
  return `${name} produced no output (exit ${result.code})${detail ? `: ${detail}` : ""}`;
}

/**
 * @param {Record<string, object>} overrides per-engine overrides from config
 * @returns {Record<string, object>}
 */
export function resolveEngines(overrides = {}) {
  const resolved = {};

  for (const [name, definition] of Object.entries(DEFAULT_ENGINES)) {
    resolved[name] = { ...definition, ...overrides[name] };
  }

  // Allow entirely new engines to be declared in config.
  for (const [name, definition] of Object.entries(overrides)) {
    if (!resolved[name]) resolved[name] = definition;
  }

  return resolved;
}
