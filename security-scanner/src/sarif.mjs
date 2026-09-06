import { fingerprint } from "./fingerprint.mjs";
import { severityFromScore, severityFromSarifLevel } from "./severity.mjs";

/**
 * @typedef {Object} Finding
 * @property {string} repo
 * @property {string} engine
 * @property {string} ruleId
 * @property {string} severity
 * @property {string} title
 * @property {string} description
 * @property {string} file
 * @property {number} [startLine]
 * @property {string} [package]
 * @property {string} [version]
 * @property {string} [fixedVersion]
 * @property {string} [helpUri]
 * @property {string} fingerprint
 */

/**
 * Normalizes a SARIF document into our finding schema.
 *
 * Every engine we run emits SARIF, which is why this is the only parser in the
 * codebase - adding an engine means adding a command line, not a parser.
 *
 * @param {object} sarif parsed SARIF document
 * @param {{repo: string, engine: string}} context
 * @returns {Finding[]}
 */
export function findingsFromSarif(sarif, context) {
  const findings = [];

  for (const run of sarif?.runs ?? []) {
    const driver = run?.tool?.driver ?? {};
    // An engine's own name beats our label: Trivy in two modes is still Trivy,
    // but knowing which driver produced a result helps when triaging.
    const engine = context.engine || driver.name || "unknown";
    const rules = collectRules(run);

    for (const result of run?.results ?? []) {
      const rule = resolveRule(result, rules);
      const location = firstLocation(result, context.baseDir);

      const finding = {
        repo: context.repo,
        engine,
        ruleId: result.ruleId ?? rule?.id ?? "unknown",
        severity: resolveSeverity(result, rule),
        title: resolveTitle(result, rule),
        description: resolveDescription(result, rule),
        file: location.file,
        startLine: location.startLine,
        helpUri: rule?.helpUri,
        ...packageFacts(result, rule),
      };

      finding.fingerprint = fingerprint(finding);
      findings.push(finding);
    }
  }

  return findings;
}

/**
 * Rules live in tool.driver.rules, but extensions (Trivy, OSV) put theirs in
 * tool.extensions[].rules. Flattening both into one index keeps lookup simple.
 * @param {object} run
 */
function collectRules(run) {
  const byId = new Map();
  const ordered = [];

  const sources = [run?.tool?.driver, ...(run?.tool?.extensions ?? [])];
  for (const source of sources) {
    for (const rule of source?.rules ?? []) {
      ordered.push(rule);
      if (rule?.id) byId.set(rule.id, rule);
    }
  }

  return { byId, ordered };
}

function resolveRule(result, rules) {
  if (result.ruleId && rules.byId.has(result.ruleId)) {
    return rules.byId.get(result.ruleId);
  }
  // ruleIndex is only meaningful against the driver's own rule array, but it is
  // the only handle some engines give us when ruleId is absent.
  if (Number.isInteger(result.ruleIndex) && rules.ordered[result.ruleIndex]) {
    return rules.ordered[result.ruleIndex];
  }
  return undefined;
}

function resolveSeverity(result, rule) {
  const raw =
    result?.properties?.["security-severity"] ??
    rule?.properties?.["security-severity"];

  const score = Number.parseFloat(raw);
  if (Number.isFinite(score)) {
    return severityFromScore(score);
  }

  // Some engines emit a plain word instead of a score.
  const tag = result?.properties?.severity ?? rule?.properties?.severity;
  if (typeof tag === "string") {
    const normalized = tag.toLowerCase();
    if (["critical", "high", "medium", "low", "info"].includes(normalized)) {
      return normalized;
    }
  }

  return severityFromSarifLevel(result.level ?? rule?.defaultConfiguration?.level);
}

function resolveTitle(result, rule) {
  const candidate =
    rule?.shortDescription?.text ??
    result?.message?.text ??
    rule?.fullDescription?.text ??
    result.ruleId ??
    "Untitled finding";

  return firstLine(candidate).slice(0, 200);
}

function resolveDescription(result, rule) {
  return (
    result?.message?.text ??
    rule?.fullDescription?.text ??
    rule?.shortDescription?.text ??
    ""
  );
}

function firstLocation(result, baseDir) {
  const physical = result?.locations?.[0]?.physicalLocation;
  const uri = physical?.artifactLocation?.uri ?? "";

  return {
    file: normalizeUri(uri, baseDir),
    startLine: physical?.region?.startLine,
  };
}

/**
 * Scanners disagree on whether to emit a bare path, a file:// URI, or an
 * absolute path inside the runner's workspace. Issues must be readable by a
 * human, so reduce all three to a repo-relative path.
 * @param {string} uri
 */
export function normalizeUri(uri, baseDir) {
  let path = String(uri ?? "").replace(/^file:\/\//, "");

  // Engines report absolute paths inside whatever directory was scanned. That
  // directory differs between a laptop and a CI runner, so leaving it in would
  // both read badly in an issue and change the fingerprint of an unchanged
  // finding depending on where the scan ran.
  if (baseDir) {
    const prefix = String(baseDir).replace(/\/+$/, "");
    if (path === prefix) {
      path = "";
    } else if (path.startsWith(prefix + "/")) {
      path = path.slice(prefix.length + 1);
    }
  }

  // Fall back to known CI layouts when the scan directory was not supplied.
  path = path.replace(/^\/?(github\/workspace|home\/runner\/work\/[^/]+\/[^/]+)\//, "");

  return path.replace(/^\.\//, "").replace(/^\/+/, "");
}

/**
 * Pulls package coordinates out of the places different engines hide them.
 * These drive both the fingerprint and the "upgrade to X" line in the issue.
 */
function packageFacts(result, rule) {
  const props = { ...rule?.properties, ...result?.properties };
  const facts = {};

  const name = props.package_name ?? props.packageName ?? props.pkgName ?? props.affected_package;
  const version = props.package_version ?? props.installedVersion ?? props.version;
  const fixed = props.fixed_version ?? props.fixedVersion ?? props.fixed;

  if (name) facts.package = String(name);
  if (version) facts.version = String(version);
  if (fixed) facts.fixedVersion = String(fixed);

  // osv-scanner puts coordinates only in the message text - it emits no result
  // properties at all - so without this every one of its findings would lose
  // its package identity. That degrades the issue text and, worse, weakens the
  // fingerprint: two packages hit by the same CVE in one lockfile would
  // otherwise collide into a single finding.
  if (!facts.package) {
    const parsed = packageFromMessage(result?.message?.text);
    if (parsed) {
      facts.package = parsed.name;
      facts.version = parsed.version;
    }
  }

  // "Upgrade to X" is the whole point of the issue, and osv-scanner leaves
  // result.fixes empty while documenting the fix in a markdown table in the
  // rule help. Recovering it turns "you have a vulnerability" into an
  // actionable instruction.
  if (!facts.fixedVersion && facts.package) {
    const fixedVersion = fixedVersionFromHelp(rule?.help?.text, facts.package);
    if (fixedVersion) facts.fixedVersion = fixedVersion;
  }

  return facts;
}

/**
 * Pulls a package's fixed version out of osv-scanner's "Fixed Versions" table:
 *
 *   | Vulnerability ID | Package Name | Fixed Version |
 *   | --- | --- | --- |
 *   | GHSA-23hp-3jrh-7fpw | tar | 7.5.19 |
 *
 * One rule can list several packages, so the row is matched by package name
 * rather than simply taking the first - otherwise a multi-package advisory
 * would recommend the wrong upgrade.
 *
 * @param {string | undefined} helpText
 * @param {string} packageName
 * @returns {string | null}
 */
export function fixedVersionFromHelp(helpText, packageName) {
  if (!helpText || !packageName) return null;

  const section = helpText.split(/###\s*Fixed Versions/i)[1];
  if (!section) return null;

  for (const line of section.split("\n")) {
    const cells = line.split("|").map((cell) => cell.trim());
    // A data row is: "", id, package, version, "" once split on the pipes.
    if (cells.length < 5) continue;
    if (cells[2] !== packageName) continue;

    const version = cells[3];
    // Skip the header separator row and anything that is not a version.
    if (!version || /^-+$/.test(version) || /fixed version/i.test(version)) continue;

    return version;
  }

  return null;
}

/**
 * Recovers "name@version" from an engine's human-readable message.
 *
 * Deliberately narrow: it only matches quoted coordinates in the phrasings
 * engines actually emit, so an unrelated message mentioning an @ sign does not
 * silently invent a package.
 *
 * @param {string | undefined} text
 * @returns {{name: string, version: string} | null}
 */
export function packageFromMessage(text) {
  if (!text) return null;

  const patterns = [
    // osv-scanner: Package 'tar@7.5.2' is vulnerable to 'CVE-...'
    /Package '([^']+)@([^'@]+)' is vulnerable/i,
    // Generic: package "foo@1.2.3"
    /\bpackage ["']([^"']+)@([^"'@]+)["']/i,
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match && match[1] && match[2]) {
      return { name: match[1], version: match[2] };
    }
  }

  return null;
}

function firstLine(text) {
  return String(text ?? "").split("\n")[0].trim();
}
