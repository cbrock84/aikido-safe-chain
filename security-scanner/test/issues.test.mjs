import test from "node:test";
import assert from "node:assert/strict";

import {
  planIssueSync,
  issueBody,
  issueTitle,
  engineMarker,
  digestBody,
  syncIssues,
} from "../src/issues.mjs";
import { fingerprint, parseFingerprint, fingerprintMarker } from "../src/fingerprint.mjs";

function makeFinding(overrides = {}) {
  const finding = {
    repo: "acme/api",
    engine: "osv-scanner",
    ruleId: "CVE-1",
    severity: "high",
    title: "Prototype pollution",
    description: "Bad things",
    file: "package-lock.json",
    package: "lodash",
    version: "4.17.20",
    ...overrides,
  };
  finding.fingerprint = fingerprint(finding);
  return finding;
}

function asIssue(finding, number = 1) {
  return { number, title: issueTitle(finding), body: issueBody(finding) };
}

test("fingerprints are stable across runs but distinguish findings", () => {
  const a = makeFinding();
  const b = makeFinding();
  assert.equal(a.fingerprint, b.fingerprint);

  assert.notEqual(makeFinding({ package: "express" }).fingerprint, a.fingerprint);
  assert.notEqual(makeFinding({ file: "other.json" }).fingerprint, a.fingerprint);
  assert.notEqual(makeFinding({ ruleId: "CVE-9" }).fingerprint, a.fingerprint);
});

test("a shifted line number does not change identity", () => {
  const a = makeFinding({ startLine: 10 });
  const b = makeFinding({ startLine: 4000 });
  assert.equal(a.fingerprint, b.fingerprint, "issues must not churn when a file grows");
});

test("issue bodies round-trip their fingerprint", () => {
  const finding = makeFinding();
  assert.equal(parseFingerprint(issueBody(finding)), finding.fingerprint);
});

test("creates issues for findings with no matching issue", () => {
  const finding = makeFinding();
  const plan = planIssueSync([finding], [], new Set(["osv-scanner"]));

  assert.equal(plan.create.length, 1);
  assert.equal(plan.close.length, 0);
  assert.match(plan.create[0].title, /lodash@4\.17\.20/);
});

test("leaves an unchanged finding untouched", () => {
  const finding = makeFinding();
  const plan = planIssueSync([finding], [asIssue(finding)], new Set(["osv-scanner"]));

  assert.equal(plan.unchanged.length, 1);
  assert.equal(plan.update.length, 0);
  assert.equal(plan.create.length, 0);
});

test("updates an issue when the finding's detail changes", () => {
  const before = makeFinding();
  const issue = asIssue(before);
  // Same identity, new fix information.
  const after = makeFinding({ fixedVersion: "4.17.21" });

  const plan = planIssueSync([after], [issue], new Set(["osv-scanner"]));
  assert.equal(plan.update.length, 1);
  assert.match(plan.update[0].body, /4\.17\.21/);
});

test("closes an issue whose finding is gone and whose engine ran", () => {
  const finding = makeFinding();
  const plan = planIssueSync([], [asIssue(finding)], new Set(["osv-scanner"]));

  assert.equal(plan.close.length, 1);
});

test("does NOT close issues from an engine that failed to run", () => {
  // The core safety property: a missing binary produces zero findings, which
  // must never be mistaken for "everything it reported is now fixed".
  const finding = makeFinding();
  const plan = planIssueSync([], [asIssue(finding)], new Set(["trivy"]));

  assert.equal(plan.close.length, 0, "a failed engine must not close its own findings");
});

test("closes only the findings of engines that ran, in a mixed batch", () => {
  const osv = makeFinding({ engine: "osv-scanner", ruleId: "CVE-1" });
  const trivy = makeFinding({ engine: "trivy", ruleId: "CVE-2" });

  const plan = planIssueSync(
    [],
    [asIssue(osv, 1), asIssue(trivy, 2)],
    new Set(["osv-scanner"])
  );

  assert.equal(plan.close.length, 1);
  assert.equal(plan.close[0].issue.number, 1);
});

test("ignores issues that carry no fingerprint marker", () => {
  const humanIssue = { number: 7, title: "Please fix the login page", body: "no marker here" };
  const plan = planIssueSync([], [humanIssue], new Set(["osv-scanner"]));

  assert.equal(plan.close.length, 0);
  assert.equal(plan.update.length, 0);
});

test("never closes the digest issue as if it were a finding", () => {
  const digest = { number: 5, title: "digest", body: fingerprintMarker("digest:acme/api") };
  const plan = planIssueSync([], [digest], new Set(["osv-scanner"]));

  assert.equal(plan.close.length, 0);
});

test("the engine marker is what drives the close decision", () => {
  const finding = makeFinding({ engine: "gitleaks" });
  assert.match(issueBody(finding), new RegExp(engineMarker("gitleaks")));
});

test("digest body lists findings worst-first and escapes table pipes", () => {
  const body = digestBody("acme/api", [
    makeFinding({ severity: "low", title: "Low thing" }),
    makeFinding({ severity: "medium", title: "Pipe | in title" }),
  ]);

  assert.ok(body.indexOf("Pipe") < body.indexOf("Low thing"), "medium should sort above low");
  assert.match(body, /Pipe \\\| in title/);
});

/** Records calls instead of hitting the network. */
function fakeClient(existing = []) {
  const calls = [];
  return {
    calls,
    async paginate() {
      return existing;
    },
    async request(method, url, body) {
      calls.push({ method, url, body });
      if (method === "GET") throw new Error("not found");
      return { number: 99 };
    },
  };
}

test("syncIssues only opens issues at or above the threshold", async () => {
  const client = fakeClient();
  const findings = [
    makeFinding({ severity: "critical", ruleId: "C1" }),
    makeFinding({ severity: "high", ruleId: "H1" }),
    makeFinding({ severity: "medium", ruleId: "M1" }),
    makeFinding({ severity: "low", ruleId: "L1" }),
  ];

  const summary = await syncIssues(client, "acme/api", findings, {
    issueThreshold: "high",
    digestThreshold: "low",
    strategy: "hybrid",
    succeededEngines: new Set(["osv-scanner"]),
    logger: { log() {}, warn() {} },
  });

  // Two issues at/above high, plus one digest covering medium and low.
  assert.equal(summary.created, 3);

  const created = client.calls.filter((c) => c.method === "POST" && c.url.endsWith("/issues"));
  const digest = created.find((c) => c.body.title.startsWith("Security scan digest"));
  assert.ok(digest, "expected a digest issue");
  assert.match(digest.body.body, /2 finding\(s\) below the issue threshold/);
});

test("dry run reports a plan without calling the write API", async () => {
  const client = fakeClient();
  const summary = await syncIssues(client, "acme/api", [makeFinding()], {
    issueThreshold: "high",
    succeededEngines: new Set(["osv-scanner"]),
    dryRun: true,
    logger: { log() {}, warn() {} },
  });

  assert.equal(summary.created, 1);
  assert.equal(client.calls.length, 0, "dry run must not write");
});

test("pull requests returned by the issues endpoint are ignored", async () => {
  const finding = makeFinding();
  const client = fakeClient([{ ...asIssue(finding), pull_request: { url: "x" } }]);

  const summary = await syncIssues(client, "acme/api", [finding], {
    issueThreshold: "high",
    succeededEngines: new Set(["osv-scanner"]),
    dryRun: true,
    logger: { log() {}, warn() {} },
  });

  // The PR must not be treated as an existing issue, so the finding is new.
  assert.equal(summary.created, 1);
});
