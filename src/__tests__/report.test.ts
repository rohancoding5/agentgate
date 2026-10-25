import { test } from "node:test";
import assert from "node:assert/strict";
import { renderResult } from "../report.js";
import type { InspectionResult } from "../types.js";

test("renderResult reports a clean allow with no findings", () => {
  const output = renderResult({ verdict: "allow", findings: [] });
  assert.match(output, /VERDICT: ALLOW/);
  assert.match(output, /no findings/);
});

test("renderResult lists every finding with severity and detail", () => {
  const result: InspectionResult = {
    verdict: "block",
    findings: [
      {
        category: "prompt_injection",
        severity: "high",
        rule: "ignore_previous_instructions",
        detail: "content attempts to override prior instructions",
        excerpt: "ignore all previous instructions",
      },
    ],
  };
  const output = renderResult(result);
  assert.match(output, /VERDICT: BLOCK/);
  assert.match(output, /\[HIGH\] prompt_injection \/ ignore_previous_instructions/);
  assert.match(output, /override prior instructions/);
  assert.match(output, /ignore all previous instructions/);
});
