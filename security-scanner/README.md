# security-scanner

Runs a set of open-source security engines across a list of repositories on a
schedule, normalizes everything they report into one schema, and keeps GitHub
issues in sync with the current findings.

Issues are opened when a finding appears, updated when its detail changes, and
closed automatically when it stops being reported.

## Design

Every engine emits SARIF, so there is exactly one parser (`src/sarif.mjs`)
rather than one per tool. Adding an engine is a config entry — a binary name and
an argv template — not new code.

```
repos.json ─> engines (SARIF) ─┐
                               ├─> normalize ─> dedupe ─> GitHub issues
SBOM (syft) ─> malware feed ───┘                      └─> merged SARIF (optional)
```

The malware check matches a CycloneDX SBOM against the Aikido Intel feed rather
than parsing lockfiles directly. Syft already handles every lockfile format
correctly, so new ecosystems come for free as Syft learns them.

## Engines

| Engine | Covers | Default |
| --- | --- | --- |
| `osv-scanner` | Dependency vulnerabilities (osv.dev) | on |
| `trivy` | Vulnerabilities, IaC misconfiguration, secrets | on |
| `gitleaks` | Hardcoded secrets | on |
| `zizmor` | GitHub Actions workflow security | on |
| `syft` | CycloneDX SBOM; required by the malware check | on |
| `aikido-malware-feed` | Malicious packages (npm, PyPI) | on |
| `checkov` | Infrastructure-as-code | off — needs tuning |
| `opengrep` | Static analysis (SAST) | off — needs a rule set |

Engine CLIs change flags between majors. Override `args` in `engineOverrides`
rather than patching `src/engines.mjs`.

## Quick start

```bash
cd security-scanner
npm test                                   # 86 tests, no network, no binaries

# Scan a local checkout without touching GitHub
node src/index.mjs scan --repo owner/name --dir /path/to/checkout

# Plan the issue changes without writing them
GITHUB_TOKEN=... node src/index.mjs run --repo owner/name --dir . --dry-run
```

Then edit `config/repos.json` and let `.github/workflows/security-scan.yml` run
it daily. `config/repos.example.json` shows every available knob.

## Configuration

Any key under `defaults` can be overridden per repo.

| Key | Default | Meaning |
| --- | --- | --- |
| `engines` | 5 engines above | Which engines to run |
| `issueThreshold` | `high` | Minimum severity that gets its own issue |
| `digestThreshold` | `low` | Minimum severity included in the digest issue |
| `issueStrategy` | `hybrid` | `per-finding`, `digest`, or `hybrid` |
| `label` | `security-scan` | Label applied to every issue we manage |
| `malware` | `true` | Run the Aikido feed check |
| `malwareFeedBaseUrl` | Aikido's | Point at your own mirror if you host one |
| `uploadSarif` | `false` | Also push results to code scanning |
| `branch` | `null` | Branch to check out; defaults to the repo default |

`hybrid` — the default — opens a dedicated issue per finding at or above
`issueThreshold` and rolls everything below it into a single digest issue, so a
long tail of lows does not bury the backlog.

## Tokens and permissions

The workflow needs a `SCAN_TOKEN` secret (PAT or GitHub App installation token)
with, on every target repo:

- `contents: read` — to check the repo out
- `issues: write` — to file findings there
- `security_events: write` — only for repos with `uploadSarif: true`

The default `GITHUB_TOKEN` is not enough: it is scoped to the repo the workflow
runs in, and this scanner runs centrally against many.

### Scanning across more than one owner

The repo list may span several owners, and a single token has to cover all of
them. The usual mistake is a token that works for one org and silently not the
other. GitHub reports that as a **404 rather than a 403**, so it reads as "no
such repo" when the repo is simply invisible to the token.

The workflow runs an access preflight before each checkout and turns that into
a message naming the real cause. Two things to check when it fires:

- A **PAT** must be granted the second org, and if that org enforces SAML SSO
  the token must additionally be *authorized* for it.
- A **GitHub App** token only covers orgs the app is actually installed on.

Because the matrix runs with `fail-fast: false`, one inaccessible repo fails
only its own job; the rest of the sweep still completes.

## SARIF upload

Optional and off by default. Uploading goes through the code scanning API rather
than `github/codeql-action/upload-sarif`, because that action can only upload to
the repository it runs in.

Code scanning is free on public repos. **On private repos it requires GitHub
Advanced Security**, so on a private estate without GHAS the issues are the
output and `uploadSarif` should stay off. A failed upload is logged and does not
fail the run — the issues are already synced by that point.

## Behaviour worth knowing

**Feed verdicts are not all malware.** The Aikido feed carries `MALWARE`,
`TELEMETRY` and `PROTESTWARE`. safe-chain itself only blocks installs on
`MALWARE`, and this scanner follows suit: `MALWARE` is critical with
remove-immediately guidance, the other two are medium and framed as policy
judgements. An unrecognized verdict is surfaced as medium rather than dropped.

**"Nothing to scan" is not a failure.** Some engines write no output at all
when a repo has no manifests (osv-scanner exits 128). That is a clean empty
result, declared per engine via `noFindingsExitCodes`. Treating it as a failure
would be actively harmful, because of the next rule.

**A failed engine never closes issues.** An engine that crashes or is missing
reports zero findings, which must not be read as "everything it previously
reported is fixed". Only issues belonging to engines that completed this run are
eligible for closing. This is the single most important correctness property
here and it is covered by tests.

**Fingerprints ignore line numbers.** Identity is
`repo|engine|ruleId|file|package|version`, so an unrelated edit that shifts a
file does not close and reopen every issue in it.

**Scanner exit codes are not failure.** Most of these tools exit non-zero to mean
"findings present". Success is judged by whether usable output was produced.

**The GitHub API is retried with backoff.** Rate limits arrive as a 429 *or* a
403 with no remaining quota, and both are retried, preferring the server's own
`retry-after` or reset time over a guess. Ordinary 4xx responses are not
retried, and a reset further out than a minute fails with the reset time rather
than idling a CI runner for an hour.

**`--fail-on` is opt-in.** A daily sweep records findings without failing; a
pre-merge gate wants the opposite. An unrecognized severity is a hard error
(exit 1) rather than a gate that fails on everything. A breached gate exits 2.

## Relationship to safe-chain

This scanner is *detection*: it tells you what is already in a repo. safe-chain
is *prevention*: it blocks malicious packages at install time, before the code
executes. They address different halves of the problem and are best run
together.

The scanner invokes no safe-chain code and does not link against it — safe-chain
is installed separately into CI via its own installer. Keeping them at arm's
length means this tool carries none of safe-chain's licensing constraints.

## Engine downloads

Every engine binary is pinned by **version and sha256**, downloaded to a file
and verified before it is unpacked or executed. The previous
`curl ... | tar xz` form ran whatever the network returned, which is exactly
the supply chain risk this scanner exists to catch.

The osv-scanner, trivy, gitleaks and syft hashes come from each project's own
published checksum file. zizmor publishes no checksum file, so its hash was
computed from the downloaded artifact: that still makes any future change to
the artifact fail loudly, but it is not an independent authenticity check the
way the other four are.

To bump an engine, change its version **and** its hash together. A mismatch
fails the job rather than scanning with an unexpected binary.

## Hardening backlog

Known gaps, listed rather than hidden:

- `checkov` and `opengrep` are wired up but untuned; enabling them as-is will be
  noisy until you supply a rule policy.
- Findings are not persisted between runs, so "first seen" dates come from the
  issue's own creation date rather than the scanner.
- Engine downloads are not signature-verified (cosign/sigstore) even where
  upstream publishes signatures; hashes catch tampering after the fact but do
  not establish provenance.
- `zizmor`'s online audits query the GitHub API and abort with 401 rather than
  degrading if no token is present. The workflow passes `GH_TOKEN`; for local
  runs without one, add `--offline` to its args via `engineOverrides`.
