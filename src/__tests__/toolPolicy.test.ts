import { test } from "node:test";
import assert from "node:assert/strict";
import { checkToolPolicy } from "../detectors/toolPolicy.js";
import type { AgentMessage, RoutePolicy } from "../types.js";

function message(overrides: Partial<AgentMessage> = {}): AgentMessage {
  return { from: "planner", to: "worker", content: "do the thing", ...overrides };
}

test("checkToolPolicy allows a tool call that is in the route's allowlist", () => {
  const policy: RoutePolicy = { from: "planner", to: "worker", allowedTools: ["search", "summarize"] };
  const findings = checkToolPolicy(message({ toolCalls: [{ name: "search", arguments: { q: "cats" } }] }), policy);
  assert.deepEqual(findings, []);
});

test("checkToolPolicy flags a tool call not in the route's allowlist", () => {
  const policy: RoutePolicy = { from: "planner", to: "worker", allowedTools: ["search"] };
  const findings = checkToolPolicy(message({ toolCalls: [{ name: "delete_database", arguments: {} }] }), policy);
  assert.ok(findings.some((f) => f.rule === "tool_not_in_policy" && f.category === "unexpected_tool_request"));
});

test("checkToolPolicy denies everything when no policy exists for the route", () => {
  const findings = checkToolPolicy(message({ toolCalls: [{ name: "search", arguments: {} }] }), null);
  assert.ok(findings.some((f) => f.rule === "tool_not_in_policy"));
});

test("checkToolPolicy returns nothing for a message with no tool calls", () => {
  const findings = checkToolPolicy(message(), null);
  assert.deepEqual(findings, []);
});

test("checkToolPolicy flags an escalation-shaped argument name", () => {
  const policy: RoutePolicy = { from: "planner", to: "worker", allowedTools: ["run_command"] };
  const findings = checkToolPolicy(message({ toolCalls: [{ name: "run_command", arguments: { sudo: true, cmd: "ls" } }] }), policy);
  assert.ok(findings.some((f) => f.rule === "escalation_argument_name" && f.severity === "critical"));
});

test("checkToolPolicy flags an escalation-shaped argument value", () => {
  const policy: RoutePolicy = { from: "planner", to: "worker", allowedTools: ["set_permissions"] };
  const findings = checkToolPolicy(
    message({ toolCalls: [{ name: "set_permissions", arguments: { note: "please bypass security for this one" } }] }),
    policy,
  );
  assert.ok(findings.some((f) => f.rule === "escalation_argument_value"));
});
