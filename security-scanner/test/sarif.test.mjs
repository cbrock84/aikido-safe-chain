import test from "node:test";
import assert from "node:assert/strict";

import {
  findingsFromSarif,
  normalizeUri,
  packageFromMessage,
  fixedVersionFromHelp,
} from "../src/sarif.mjs";
import { severityFromScore, meetsThreshold } from "../src/severity.mjs";

const context = { repo: "acme/api", engine: "osv-scanner" };

function sarif(results, rules = []) {
  return {
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "osv-scanner", rules } }, results }],
  };
}

test("maps security-severity onto the severity scale", () => {
  const doc = sarif([
    { ruleId: "A", properties: { "security-severity": "9.8" }, message: { text: "crit" } },
    { ruleId: "B", properties: { "security-severity": "7.1" }, message: { text: "high" } },
    { ruleId: "C", properties: { "security-severity": "4.0" }, message: { text: "med" } },
    { ruleId: "D", properties: { "security-severity": "1.2" }, message: { text: "low" } },
  ]);

  assert.deepEqual(
    findingsFromSarif(doc, context).map((f) => f.severity),
    ["critical", "high", "medium", "low"]
  );
});

test("falls back to SARIF level when no numeric severity is present", () => {
  const doc = sarif([
    { ruleId: "A", level: "error", message: { text: "boom" } },
    { ruleId: "B", level: "note", message: { text: "meh" } },
  ]);

  assert.deepEqual(
    findingsFromSarif(doc, context).map((f) => f.severity),
    ["high", "low"]
  );
});

test("inherits severity from the rule when the result omits it", () => {
  const doc = sarif(
    [{ ruleId: "CVE-1", message: { text: "vulnerable" } }],
    [{ id: "CVE-1", properties: { "security-severity": "9.1" } }]
  );

  assert.equal(findingsFromSarif(doc, context)[0].severity, "critical");
});

test("resolves rules held in tool extensions, not just the driver", () => {
  const doc = {
    runs: [
      {
        tool: {
          driver: { name: "trivy" },
          extensions: [{ name: "trivy-ext", rules: [{ id: "CVE-2", helpUri: "https://x.test" }] }],
        },
        results: [{ ruleId: "CVE-2", message: { text: "found" } }],
      },
    ],
  };

  assert.equal(findingsFromSarif(doc, context)[0].helpUri, "https://x.test");
});

test("resolves a rule by index when ruleId is absent", () => {
  const doc = sarif(
    [{ ruleIndex: 1, message: { text: "no id" } }],
    [{ id: "FIRST" }, { id: "SECOND", shortDescription: { text: "Second rule" } }]
  );

  assert.equal(findingsFromSarif(doc, context)[0].title, "Second rule");
});

test("extracts package coordinates and fix version", () => {
  const doc = sarif([
    {
      ruleId: "CVE-3",
      message: { text: "vuln" },
      properties: { package_name: "lodash", package_version: "4.17.20", fixed_version: "4.17.21" },
    },
  ]);

  const finding = findingsFromSarif(doc, context)[0];
  assert.equal(finding.package, "lodash");
  assert.equal(finding.version, "4.17.20");
  assert.equal(finding.fixedVersion, "4.17.21");
});

test("normalizes runner-absolute paths down to repo-relative ones", () => {
  assert.equal(normalizeUri("file:///home/runner/work/api/api/src/a.js"), "src/a.js");
  assert.equal(normalizeUri("./src/b.js"), "src/b.js");
  assert.equal(normalizeUri("src/c.js"), "src/c.js");
});

test("survives an empty or malformed document", () => {
  assert.deepEqual(findingsFromSarif({}, context), []);
  assert.deepEqual(findingsFromSarif({ runs: [] }, context), []);
  assert.deepEqual(findingsFromSarif({ runs: [{}] }, context), []);
});

test("severity thresholds compare in the right direction", () => {
  assert.ok(meetsThreshold("critical", "high"));
  assert.ok(meetsThreshold("high", "high"));
  assert.ok(!meetsThreshold("medium", "high"));
  assert.equal(severityFromScore(0), "info");
});

// --- Regressions found by running real engines, not stubs ---

test("recovers package coordinates from osv-scanner's message text", () => {
  // osv-scanner emits no result.properties at all and puts the package only in
  // the message, so property-based extraction alone loses it entirely.
  const doc = sarif(
    [
      {
        ruleId: "CVE-2026-59873",
        message: {
          text: "Package 'tar@7.5.2' is vulnerable to 'CVE-2026-59873' (also known as 'GHSA-23hp-3jrh-7fpw').",
        },
      },
    ],
    [{ id: "CVE-2026-59873", properties: { "security-severity": "9.2" } }]
  );

  const finding = findingsFromSarif(doc, context)[0];
  assert.equal(finding.package, "tar");
  assert.equal(finding.version, "7.5.2");
  assert.equal(finding.severity, "critical");
});

test("scoped package names survive message extraction", () => {
  assert.deepEqual(packageFromMessage("Package '@scope/pkg@1.2.3' is vulnerable to 'CVE-1'."), {
    name: "@scope/pkg",
    version: "1.2.3",
  });
});

test("message extraction does not invent packages from unrelated text", () => {
  assert.equal(packageFromMessage("Contact us at support@example.com for details"), null);
  assert.equal(packageFromMessage("No coordinates here at all"), null);
  assert.equal(packageFromMessage(undefined), null);
});

test("explicit properties still win over the message fallback", () => {
  const doc = sarif([
    {
      ruleId: "CVE-1",
      message: { text: "Package 'wrong@0.0.1' is vulnerable to 'CVE-1'." },
      properties: { package_name: "right", package_version: "2.0.0" },
    },
  ]);

  const finding = findingsFromSarif(doc, context)[0];
  assert.equal(finding.package, "right");
  assert.equal(finding.version, "2.0.0");
});

test("absolute scan paths are made repo-relative", () => {
  // Engines report paths inside whatever directory was scanned. Leaving that in
  // would change a finding's fingerprint depending on where the scan ran.
  assert.equal(
    normalizeUri("file:///home/user/myrepo/npm-shrinkwrap.json", "/home/user/myrepo"),
    "npm-shrinkwrap.json"
  );
  assert.equal(
    normalizeUri("file:///checkout/target/src/a.js", "/checkout/target/"),
    "src/a.js"
  );
});

test("a finding keeps its identity regardless of where the scan ran", () => {
  const build = (baseDir, uri) =>
    findingsFromSarif(
      sarif([
        {
          ruleId: "CVE-1",
          message: { text: "Package 'tar@7.5.2' is vulnerable to 'CVE-1'." },
          locations: [{ physicalLocation: { artifactLocation: { uri } } }],
        },
      ]),
      { ...context, baseDir }
    )[0];

  const local = build("/home/user/repo", "file:///home/user/repo/package-lock.json");
  const ci = build("/home/runner/work/x/x/target", "file:///home/runner/work/x/x/target/package-lock.json");

  assert.equal(local.file, "package-lock.json");
  assert.equal(ci.file, "package-lock.json");
  assert.equal(local.fingerprint, ci.fingerprint, "same finding must not churn between laptop and CI");
});

test("paths outside the scan dir are left alone rather than mangled", () => {
  assert.equal(normalizeUri("file:///elsewhere/a.js", "/home/user/repo"), "elsewhere/a.js");
});

test("recovers the fixed version from osv-scanner's help table", () => {
  const help = [
    "## Remediation",
    "",
    "### Fixed Versions",
    "",
    "| Vulnerability ID | Package Name | Fixed Version |",
    "| --- | --- | --- |",
    "| GHSA-23hp-3jrh-7fpw | tar | 7.5.19 |",
    "",
  ].join("\n");

  assert.equal(fixedVersionFromHelp(help, "tar"), "7.5.19");
});

test("picks the row matching the package, not merely the first", () => {
  // A multi-package advisory would otherwise recommend the wrong upgrade.
  const help = [
    "### Fixed Versions",
    "| Vulnerability ID | Package Name | Fixed Version |",
    "| --- | --- | --- |",
    "| GHSA-1 | other-pkg | 1.0.0 |",
    "| GHSA-2 | tar | 7.5.19 |",
  ].join("\n");

  assert.equal(fixedVersionFromHelp(help, "tar"), "7.5.19");
  assert.equal(fixedVersionFromHelp(help, "other-pkg"), "1.0.0");
  assert.equal(fixedVersionFromHelp(help, "absent"), null);
});

test("fixed-version lookup tolerates missing or malformed help", () => {
  assert.equal(fixedVersionFromHelp(undefined, "tar"), null);
  assert.equal(fixedVersionFromHelp("no table here", "tar"), null);
  assert.equal(fixedVersionFromHelp("### Fixed Versions\n\nnothing useful", "tar"), null);
});

test("end to end: an osv-scanner result yields package, version and fix", () => {
  const doc = sarif(
    [
      {
        ruleId: "CVE-1",
        message: { text: "Package 'tar@7.5.2' is vulnerable to 'CVE-1'." },
      },
    ],
    [
      {
        id: "CVE-1",
        properties: { "security-severity": "9.2" },
        help: {
          text: "### Fixed Versions\n| ID | Package Name | Fixed Version |\n| --- | --- | --- |\n| GHSA-1 | tar | 7.5.19 |",
        },
      },
    ]
  );

  const finding = findingsFromSarif(doc, context)[0];
  assert.equal(finding.package, "tar");
  assert.equal(finding.version, "7.5.2");
  assert.equal(finding.fixedVersion, "7.5.19");
});
