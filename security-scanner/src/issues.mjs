import { fingerprintMarker, parseFingerprint } from "./fingerprint.mjs";
import { meetsThreshold, severityRank } from "./severity.mjs";

const API = "https://api.github.com";
const ENGINE_MARKER = /<!--\s*security-scan:engine=([a-z0-9._-]+)\s*-->/i;

/** @param {string} engine */
export function engineMarker(engine) {
  return `<!-- security-scan:engine=${engine} -->`;
}

/**
 * Minimal GitHub REST client. Octokit would work too, but keeping this
 * dependency-free means the scanner runs from a bare Node install with nothing
 * to audit but our own code - which matters for a tool whose whole job is
 * supply chain hygiene.
 */
export function createClient(token, fetchImpl = fetch) {
  async function request(method, url, body) {
    const response = await fetchImpl(url.startsWith("http") ? url : `${API}${url}`, {
      method,
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "x-github-api-version": "2022-11-28",
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`GitHub ${method} ${url} -> ${response.status}: ${text.slice(0, 300)}`);
    }

    // 204 responses carry no body.
    return response.status === 204 ? null : response.json();
  }

  return {
    request,

    /** Walks all pages; a repo with 200 open findings must not silently truncate at 100. */
    async paginate(url) {
      const results = [];
      let page = 1;

      for (;;) {
        const separator = url.includes("?") ? "&" : "?";
        const batch = await request("GET", `${url}${separator}per_page=100&page=${page}`);
        if (!Array.isArray(batch) || batch.length === 0) break;

        results.push(...batch);
        if (batch.length < 100) break;

        page += 1;
        if (page > 50) break; // Guard against an unbounded loop on API weirdness.
      }

      return results;
    },
  };
}

/**
 * @param {object} finding
 * @returns {string}
 */
export function issueTitle(finding) {
  const scope = finding.package
    ? `${finding.package}@${finding.version ?? "*"}`
    : finding.file || "repository";

  return `[${finding.severity}] ${finding.title} (${scope})`.slice(0, 250);
}

/**
 * @param {object} finding
 * @returns {string}
 */
export function issueBody(finding) {
  const lines = [
    fingerprintMarker(finding.fingerprint),
    engineMarker(finding.engine),
    "",
    `**Severity:** ${finding.severity}`,
    `**Engine:** ${finding.engine}`,
    `**Rule:** ${finding.ruleId}`,
  ];

  if (finding.package) {
    lines.push(`**Package:** \`${finding.package}@${finding.version ?? "unknown"}\``);
  }
  if (finding.fixedVersion) {
    lines.push(`**Fixed in:** \`${finding.fixedVersion}\``);
  }
  if (finding.file) {
    const location = finding.startLine ? `${finding.file}:${finding.startLine}` : finding.file;
    lines.push(`**Location:** \`${location}\``);
  }

  lines.push("", "---", "", finding.description || "_No further detail provided._");

  if (finding.fixedVersion && finding.package) {
    lines.push(
      "",
      "### Suggested fix",
      "",
      `Upgrade \`${finding.package}\` to \`${finding.fixedVersion}\` or later.`
    );
  }

  if (finding.helpUri) {
    lines.push("", `[More information](${finding.helpUri})`);
  }

  lines.push(
    "",
    "---",
    "_Opened automatically by security-scanner. It closes on its own once the finding no longer appears in a scan._"
  );

  return lines.join("\n");
}

/**
 * Rolls low-severity findings into a single issue so the backlog stays legible.
 * @param {string} repo
 * @param {object[]} findings
 */
export function digestBody(repo, findings) {
  const sorted = [...findings].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity)
  );

  const lines = [
    fingerprintMarker(`digest:${repo}`),
    "",
    `${findings.length} finding(s) below the issue threshold, listed here rather than as separate issues.`,
    "",
    "| Severity | Engine | Finding | Location |",
    "| --- | --- | --- | --- |",
  ];

  for (const finding of sorted.slice(0, 200)) {
    const location = finding.package
      ? `\`${finding.package}@${finding.version ?? "*"}\``
      : `\`${finding.file || "-"}\``;
    lines.push(
      `| ${finding.severity} | ${finding.engine} | ${escapeCell(finding.title)} | ${location} |`
    );
  }

  if (sorted.length > 200) {
    lines.push("", `_...and ${sorted.length - 200} more._`);
  }

  lines.push("", "_Rewritten on each scan by security-scanner._");
  return lines.join("\n");
}

function escapeCell(text) {
  return String(text ?? "").replaceAll("|", "\\|").slice(0, 160);
}

/**
 * Reconciles findings against the issues already open on a repo.
 *
 * The subtle correctness requirement: an engine that failed to run this time
 * produces zero findings, which must NOT be read as "everything it previously
 * reported is fixed". Only issues belonging to engines that actually completed
 * are eligible for closing - otherwise a missing binary quietly closes every
 * real finding it had reported.
 *
 * @param {object[]} findings findings at or above the issue threshold
 * @param {object[]} existingIssues open issues carrying our label
 * @param {Set<string>} succeededEngines engines that completed this run
 */
export function planIssueSync(findings, existingIssues, succeededEngines) {
  const byFingerprint = new Map(findings.map((f) => [f.fingerprint, f]));
  const seen = new Set();

  const plan = { create: [], update: [], close: [], unchanged: [] };

  for (const issue of existingIssues) {
    const fp = parseFingerprint(issue.body ?? "");
    if (!fp) continue;

    seen.add(fp);
    const finding = byFingerprint.get(fp);

    if (finding) {
      const body = issueBody(finding);
      const title = issueTitle(finding);
      if (issue.body !== body || issue.title !== title) {
        plan.update.push({ issue, finding, title, body });
      } else {
        plan.unchanged.push({ issue, finding });
      }
      continue;
    }

    // Digest issues are rewritten wholesale below, never closed here.
    if (fp.startsWith("digest:")) continue;

    const engine = (issue.body ?? "").match(ENGINE_MARKER)?.[1];
    if (engine && !succeededEngines.has(engine)) {
      // The engine that raised this did not run; leave the issue alone.
      continue;
    }

    plan.close.push({ issue, engine });
  }

  for (const finding of findings) {
    if (!seen.has(finding.fingerprint)) {
      plan.create.push({
        finding,
        title: issueTitle(finding),
        body: issueBody(finding),
      });
    }
  }

  return plan;
}

/**
 * @param {object} client
 * @param {string} repo "owner/name"
 * @param {object[]} findings all findings for the repo
 * @param {object} options
 */
export async function syncIssues(client, repo, findings, options) {
  const {
    label = "security-scan",
    issueThreshold = "high",
    digestThreshold = "info",
    strategy = "hybrid",
    succeededEngines = new Set(),
    dryRun = false,
    logger = console,
  } = options;

  const actionable = findings.filter((f) => meetsThreshold(f.severity, issueThreshold));
  const belowThreshold = findings.filter(
    (f) =>
      !meetsThreshold(f.severity, issueThreshold) &&
      meetsThreshold(f.severity, digestThreshold)
  );

  const perFinding = strategy === "digest" ? [] : actionable;

  const existing = await client.paginate(
    `/repos/${repo}/issues?state=open&labels=${encodeURIComponent(label)}`
  );
  // The issues endpoint also returns pull requests; they are never ours.
  const issues = existing.filter((issue) => !issue.pull_request);

  const plan = planIssueSync(perFinding, issues, succeededEngines);
  const summary = { created: 0, updated: 0, closed: 0, unchanged: plan.unchanged.length };

  if (dryRun) {
    logger.log(
      `[dry-run] ${repo}: create ${plan.create.length}, update ${plan.update.length}, close ${plan.close.length}, unchanged ${plan.unchanged.length}`
    );
    return { ...summary, created: plan.create.length, updated: plan.update.length, closed: plan.close.length, plan };
  }

  await ensureLabel(client, repo, label);

  for (const item of plan.create) {
    await client.request("POST", `/repos/${repo}/issues`, {
      title: item.title,
      body: item.body,
      labels: [label, `severity:${item.finding.severity}`],
    });
    summary.created += 1;
  }

  for (const item of plan.update) {
    await client.request("PATCH", `/repos/${repo}/issues/${item.issue.number}`, {
      title: item.title,
      body: item.body,
    });
    summary.updated += 1;
  }

  for (const item of plan.close) {
    await client.request("POST", `/repos/${repo}/issues/${item.issue.number}/comments`, {
      body: "This finding no longer appears in the latest scan. Closing automatically.",
    });
    await client.request("PATCH", `/repos/${repo}/issues/${item.issue.number}`, {
      state: "closed",
      state_reason: "completed",
    });
    summary.closed += 1;
  }

  if (strategy !== "per-finding") {
    const digestFindings = strategy === "digest" ? [...actionable, ...belowThreshold] : belowThreshold;
    await syncDigest(client, repo, digestFindings, issues, label, summary);
  }

  return summary;
}

async function syncDigest(client, repo, findings, issues, label, summary) {
  const marker = `digest:${repo}`;
  const existing = issues.find((issue) => parseFingerprint(issue.body ?? "") === marker);

  if (findings.length === 0) {
    if (existing) {
      await client.request("PATCH", `/repos/${repo}/issues/${existing.number}`, {
        state: "closed",
        state_reason: "completed",
      });
      summary.closed += 1;
    }
    return;
  }

  const title = `Security scan digest: ${findings.length} low-severity finding(s)`;
  const body = digestBody(repo, findings);

  if (existing) {
    if (existing.body !== body || existing.title !== title) {
      await client.request("PATCH", `/repos/${repo}/issues/${existing.number}`, { title, body });
      summary.updated += 1;
    }
    return;
  }

  await client.request("POST", `/repos/${repo}/issues`, {
    title,
    body,
    labels: [label, "severity:digest"],
  });
  summary.created += 1;
}

async function ensureLabel(client, repo, label) {
  try {
    await client.request("GET", `/repos/${repo}/labels/${encodeURIComponent(label)}`);
  } catch {
    try {
      await client.request("POST", `/repos/${repo}/labels`, {
        name: label,
        color: "b60205",
        description: "Opened by security-scanner",
      });
    } catch {
      // A label we cannot create is not worth failing the run over; issue
      // creation will still succeed and GitHub creates missing labels itself.
    }
  }
}
