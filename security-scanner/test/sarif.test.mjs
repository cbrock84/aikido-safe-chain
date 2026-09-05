import test from "node:test";
import assert from "node:assert/strict";

import { findingsFromSarif, normalizeUri } from "../src/sarif.mjs";
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
