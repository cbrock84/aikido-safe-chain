import { readFile } from "node:fs/promises";

/**
 * Defaults chosen so a fresh install is useful and quiet: engines that need no
 * rule tuning are on, engines that need it (checkov, opengrep) are opt-in, and
 * only high-and-above opens its own issue.
 */
export const DEFAULTS = {
  engines: ["osv-scanner", "trivy", "gitleaks", "zizmor", "syft"],
  issueThreshold: "high",
  digestThreshold: "low",
  issueStrategy: "hybrid",
  label: "security-scan",
  malware: true,
  malwareFeedBaseUrl: "https://malware-list.aikido.dev",
  uploadSarif: false,
  branch: null,
};

/**
 * @param {string} configPath
 * @returns {Promise<{defaults: object, engineOverrides: object, repos: object[]}>}
 */
export async function loadConfig(configPath) {
  let raw;
  try {
    raw = await readFile(configPath, "utf8");
  } catch (error) {
    throw new Error(`Could not read config at ${configPath}: ${error.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Config at ${configPath} is not valid JSON: ${error.message}`);
  }

  return validateConfig(parsed);
}

/**
 * Fails loudly on a malformed config rather than scanning the wrong thing.
 * A typo in a repo name is much cheaper to catch here than three jobs later.
 * @param {object} parsed
 */
export function validateConfig(parsed) {
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Config must be a JSON object");
  }

  if (!Array.isArray(parsed.repos) || parsed.repos.length === 0) {
    throw new Error('Config must define a non-empty "repos" array');
  }

  const defaults = { ...DEFAULTS, ...parsed.defaults };
  const repos = parsed.repos.map((entry, index) => {
    const repo = typeof entry === "string" ? { name: entry } : { ...entry };

    if (!repo.name || !/^[^/\s]+\/[^/\s]+$/.test(repo.name)) {
      throw new Error(
        `repos[${index}] must have a "name" of the form "owner/repo" (got ${JSON.stringify(repo.name)})`
      );
    }

    return { ...defaults, ...repo };
  });

  const seen = new Set();
  for (const repo of repos) {
    if (seen.has(repo.name)) {
      throw new Error(`Duplicate repo in config: ${repo.name}`);
    }
    seen.add(repo.name);
  }

  return { defaults, engineOverrides: parsed.engineOverrides ?? {}, repos };
}
