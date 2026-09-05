/**
 * Severity handling.
 *
 * Every engine expresses severity differently, so we normalize onto a single
 * ordered scale. SARIF's own `level` is too coarse (error/warning/note), so we
 * prefer the numeric `security-severity` property that GitHub's code scanning
 * convention defines (0-10, CVSS-like) and fall back to `level`.
 */

/** Ordered low -> high so comparisons are just index lookups. */
export const SEVERITIES = ["info", "low", "medium", "high", "critical"];

/**
 * @param {string} severity
 * @returns {number} index into SEVERITIES, or -1 when unknown
 */
export function severityRank(severity) {
  return SEVERITIES.indexOf(String(severity).toLowerCase());
}

/**
 * @param {string} severity
 * @param {string} threshold
 * @returns {boolean} true when severity is at least threshold
 */
export function meetsThreshold(severity, threshold) {
  const s = severityRank(severity);
  const t = severityRank(threshold);

  // An unknown threshold must not silently swallow findings, so treat it as
  // the lowest bar rather than dropping everything on the floor.
  if (t === -1) return true;
  if (s === -1) return false;

  return s >= t;
}

/**
 * Maps a CVSS-style 0-10 score onto our scale using the same cutoffs GitHub
 * uses when it renders code scanning alerts.
 * @param {number} score
 * @returns {string}
 */
export function severityFromScore(score) {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}

/**
 * @param {string | undefined} level SARIF result level
 * @returns {string}
 */
export function severityFromSarifLevel(level) {
  switch (level) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    default:
      return "info";
  }
}
