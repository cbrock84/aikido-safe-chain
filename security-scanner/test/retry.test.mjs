import test from "node:test";
import assert from "node:assert/strict";

import { createClient, isRetryableResponse, retryDelayMs } from "../src/issues.mjs";

/** Minimal stand-in for a fetch Response. */
function response(status, { headers = {}, body = {}, text = "" } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (key) => headers[key.toLowerCase()] ?? null },
    json: async () => body,
    text: async () => text,
  };
}

/** Records how long each backoff waited without actually waiting. */
function recorder() {
  const waits = [];
  return { waits, sleep: async (ms) => void waits.push(ms) };
}

test("a spent rate limit is recognized as 403 as well as 429", () => {
  // GitHub returns 403 with remaining=0 for the primary limit. Treating only
  // 429 as rate limiting would turn the common case into a hard failure.
  assert.ok(isRetryableResponse(response(429)));
  assert.ok(
    isRetryableResponse(response(403, { headers: { "x-ratelimit-remaining": "0" } }))
  );
  assert.ok(isRetryableResponse(response(502)));
});

test("ordinary client errors are not retried", () => {
  assert.ok(!isRetryableResponse(response(404)));
  assert.ok(!isRetryableResponse(response(422)));
  // A 403 with quota left is a permissions problem; retrying cannot fix it.
  assert.ok(
    !isRetryableResponse(response(403, { headers: { "x-ratelimit-remaining": "42" } }))
  );
});

test("retry-after wins over our own guess", () => {
  const delay = retryDelayMs(response(429, { headers: { "retry-after": "7" } }), 0);
  assert.equal(delay, 7000);
});

test("a spent limit waits until the reset moment", () => {
  const now = 1_000_000;
  const delay = retryDelayMs(
    response(403, {
      headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String((now + 30_000) / 1000) },
    }),
    0,
    now
  );

  assert.equal(delay, 30_000);
});

test("backoff grows exponentially and is capped", () => {
  const plain = response(500);
  assert.equal(retryDelayMs(plain, 0), 1000);
  assert.equal(retryDelayMs(plain, 1), 2000);
  assert.equal(retryDelayMs(plain, 2), 4000);
  assert.equal(retryDelayMs(plain, 20), 60_000, "must not grow without bound");
});

test("a rate-limited request succeeds after backing off", async () => {
  const { waits, sleep } = recorder();
  let calls = 0;

  const fetchImpl = async () => {
    calls += 1;
    return calls < 3
      ? response(429, { headers: { "retry-after": "2" } })
      : response(200, { body: { ok: true } });
  };

  const client = createClient("t", fetchImpl, { sleep });
  assert.deepEqual(await client.request("GET", "/x"), { ok: true });
  assert.equal(calls, 3);
  assert.deepEqual(waits, [2000, 2000]);
});

test("a transient network error is retried", async () => {
  const { sleep } = recorder();
  let calls = 0;

  const fetchImpl = async () => {
    calls += 1;
    if (calls === 1) throw new Error("ECONNRESET");
    return response(200, { body: { ok: true } });
  };

  const client = createClient("t", fetchImpl, { sleep });
  assert.deepEqual(await client.request("GET", "/x"), { ok: true });
  assert.equal(calls, 2);
});

test("a 404 fails immediately without burning attempts", async () => {
  const { waits, sleep } = recorder();
  let calls = 0;

  const fetchImpl = async () => {
    calls += 1;
    return response(404, { text: "Not Found" });
  };

  const client = createClient("t", fetchImpl, { sleep });
  await assert.rejects(() => client.request("GET", "/x"), /404/);
  assert.equal(calls, 1, "a 404 is not transient");
  assert.deepEqual(waits, []);
});

test("gives up after the attempt limit rather than looping forever", async () => {
  const { sleep } = recorder();
  let calls = 0;

  const fetchImpl = async () => {
    calls += 1;
    return response(503, { text: "unavailable" });
  };

  const client = createClient("t", fetchImpl, { sleep, maxAttempts: 3 });
  await assert.rejects(() => client.request("GET", "/x"), /503/);
  assert.equal(calls, 3);
});

test("refuses to idle for a far-off rate limit reset", async () => {
  // Sleeping an hour in CI burns runner minutes and hides the problem.
  const now = 1_000_000;
  const { waits, sleep } = recorder();

  const fetchImpl = async () =>
    response(403, {
      headers: {
        "x-ratelimit-remaining": "0",
        "x-ratelimit-reset": String((now + 3_600_000) / 1000),
      },
    });

  const client = createClient("t", fetchImpl, { sleep, now: () => now });
  await assert.rejects(
    () => client.request("GET", "/x"),
    /rate limited until .* longer than this run is willing to wait/s
  );
  assert.deepEqual(waits, [], "must not sleep at all in this case");
});

test("pagination inherits the retry behaviour", async () => {
  const { sleep } = recorder();
  let calls = 0;

  const fetchImpl = async () => {
    calls += 1;
    if (calls === 1) return response(429, { headers: { "retry-after": "1" } });
    return response(200, { body: [] });
  };

  const client = createClient("t", fetchImpl, { sleep });
  assert.deepEqual(await client.paginate("/repos/a/b/issues"), []);
  assert.equal(calls, 2);
});
