import { gzipSync } from "node:zlib";
import { readFile } from "node:fs/promises";

/**
 * Uploads merged SARIF to a repo's code scanning alerts.
 *
 * Note this is the API path rather than the codeql-action, because the action
 * can only upload to the repository it runs in - and this scanner runs
 * centrally against many repositories.
 *
 * Requires the token to hold security_events:write on the target repo. Code
 * scanning is free on public repos; on private repos it needs GitHub Advanced
 * Security, which is why this is opt-in per repo and issues remain the default
 * output.
 *
 * @param {object} client
 * @param {string} repo "owner/name"
 * @param {string} sarifPath
 * @param {{commitSha: string, ref: string}} context
 */
export async function uploadSarif(client, repo, sarifPath, context) {
  const contents = await readFile(sarifPath);
  const encoded = gzipSync(contents).toString("base64");

  return client.request("POST", `/repos/${repo}/code-scanning/sarifs`, {
    commit_sha: context.commitSha,
    ref: context.ref,
    sarif: encoded,
    tool_name: "security-scanner",
  });
}

/**
 * Merges several SARIF documents into one.
 *
 * GitHub accepts multiple runs in a single document, so merging preserves each
 * engine's identity in the Security tab instead of flattening everything into
 * one indistinguishable tool.
 *
 * @param {object[]} documents
 */
export function mergeSarif(documents) {
  const runs = [];

  for (const document of documents) {
    for (const run of document?.runs ?? []) {
      runs.push(run);
    }
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs,
  };
}
