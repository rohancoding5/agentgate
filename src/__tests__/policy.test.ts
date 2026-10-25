import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { validatePolicy, findRoutePolicy, loadPolicy, defaultPolicy } from "../policy.js";
import { withTempDir } from "./test-utils.js";

test("validatePolicy accepts a well-formed policy", () => {
  const policy = validatePolicy({
    routes: [{ from: "planner", to: "worker", allowedTools: ["search"] }],
    blockThreshold: "high",
  });
  assert.equal(policy.routes.length, 1);
  assert.equal(policy.blockThreshold, "high");
});

test("validatePolicy defaults blockThreshold to high when omitted", () => {
  const policy = validatePolicy({ routes: [] });
  assert.equal(policy.blockThreshold, "high");
});

test("validatePolicy rejects a non-object", () => {
  assert.throws(() => validatePolicy("nope"), /must be a JSON object/);
});

test("validatePolicy rejects a missing routes array", () => {
  assert.throws(() => validatePolicy({}), /routes/);
});

test("validatePolicy rejects a route missing allowedTools", () => {
  assert.throws(() => validatePolicy({ routes: [{ from: "a", to: "b" }] }), /allowedTools/);
});

test("validatePolicy rejects an invalid blockThreshold", () => {
  assert.throws(() => validatePolicy({ routes: [], blockThreshold: "extreme" }), /blockThreshold/);
});

test("findRoutePolicy finds the matching route", () => {
  const policy = validatePolicy({ routes: [{ from: "a", to: "b", allowedTools: ["x"] }] });
  const route = findRoutePolicy(policy, "a", "b");
  assert.deepEqual(route, { from: "a", to: "b", allowedTools: ["x"] });
});

test("findRoutePolicy returns null when no route matches", () => {
  const policy = validatePolicy({ routes: [{ from: "a", to: "b", allowedTools: [] }] });
  assert.equal(findRoutePolicy(policy, "a", "c"), null);
});

test("loadPolicy reads and validates a real JSON file", async () => {
  await withTempDir(async (dir) => {
    const path = join(dir, "policy.json");
    await writeFile(path, JSON.stringify({ routes: [{ from: "a", to: "b", allowedTools: ["x"] }] }));
    const policy = await loadPolicy(path);
    assert.equal(policy.routes.length, 1);
  });
});

test("loadPolicy throws a clear error for malformed JSON", async () => {
  await withTempDir(async (dir) => {
    const path = join(dir, "policy.json");
    await writeFile(path, "{ not valid json");
    await assert.rejects(() => loadPolicy(path), /isn't valid JSON/);
  });
});

test("defaultPolicy has no routes and a high block threshold", () => {
  assert.deepEqual(defaultPolicy(), { routes: [], blockThreshold: "high" });
});
