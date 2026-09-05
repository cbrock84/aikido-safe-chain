import { createHash } from "node:crypto";

/**
 * Stable identity for a finding across scan runs.
 *
 * Deliberately excludes the line number: an unrelated edit that shifts a file
 * down ten lines must not close the old issue and open an identical new one.
 * File path is included because the same rule firing in two files is two
 * findings a human has to fix separately.
 *
 * @param {object} finding
 * @returns {string} 16 hex chars - short enough for an issue label, long
 *   enough that collisions are not a practical concern at repo scale.
 */
export function fingerprint(finding) {
  const parts = [
    finding.repo ?? "",
    finding.engine ?? "",
    finding.ruleId ?? "",
    finding.file ?? "",
    finding.package ?? "",
    finding.version ?? "",
  ];

  return createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 16);
}

const MARKER = "security-scan:fp=";

/**
 * Issue bodies carry their fingerprint in an HTML comment. Labels are capped
 * and user-editable; the body marker is what we actually trust when matching
 * an existing issue back to a finding.
 * @param {string} fp
 * @returns {string}
 */
export function fingerprintMarker(fp) {
  return `<!-- ${MARKER}${fp} -->`;
}

/**
 * @param {string} body
 * @returns {string | null}
 */
export function parseFingerprint(body) {
  const match = String(body ?? "").match(
    /<!--\s*security-scan:fp=([0-9a-z:.\-_/]+)\s*-->/i
  );
  return match ? match[1] : null;
}
