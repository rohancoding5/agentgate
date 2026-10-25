import { test } from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "../config.js";

test("parseArgs parses a plain inspect command with a file", () => {
  const command = parseArgs(["inspect", "message.json"]);
  assert.deepEqual(command, { command: "inspect", file: "message.json", policyPath: null, semantic: false, json: false });
});

test("parseArgs parses inspect with no file for stdin mode", () => {
  const command = parseArgs(["inspect"]);
  assert.deepEqual(command, { command: "inspect", file: null, policyPath: null, semantic: false, json: false });
});

test("parseArgs reads --policy, --semantic, and --json for inspect", () => {
  const command = parseArgs(["inspect", "message.json", "--policy", "policy.json", "--semantic", "--json"]);
  assert.deepEqual(command, { command: "inspect", file: "message.json", policyPath: "policy.json", semantic: true, json: true });
});

test("parseArgs parses serve with required --targets", () => {
  const command = parseArgs(["serve", "--targets", "targets.json"]);
  assert.deepEqual(command, { command: "serve", port: 8787, policyPath: null, targetsPath: "targets.json", semantic: false });
});

test("parseArgs reads --port, --policy, and --semantic for serve", () => {
  const command = parseArgs(["serve", "--targets", "targets.json", "--port", "9000", "--policy", "policy.json", "--semantic"]);
  assert.deepEqual(command, { command: "serve", port: 9000, policyPath: "policy.json", targetsPath: "targets.json", semantic: true });
});

test("parseArgs throws when serve has no --targets", () => {
  assert.throws(() => parseArgs(["serve"]), /needs --targets/);
});

test("parseArgs throws on a non-positive --port", () => {
  assert.throws(() => parseArgs(["serve", "--targets", "t.json", "--port", "0"]), /positive integer/);
});

test("parseArgs throws on a non-numeric --port", () => {
  assert.throws(() => parseArgs(["serve", "--targets", "t.json", "--port", "nope"]), /positive integer/);
});

test("parseArgs throws on an unknown command", () => {
  assert.throws(() => parseArgs(["scan"]), /unknown command/);
});

test("parseArgs throws on an unknown flag", () => {
  assert.throws(() => parseArgs(["inspect", "--bogus"]), /unknown flag/);
});

test("parseArgs throws when a flag is missing its value", () => {
  assert.throws(() => parseArgs(["inspect", "--policy"]), /needs a value/);
});

test("parseArgs returns null and prints help for --help", () => {
  assert.equal(parseArgs(["--help"]), null);
});

test("parseArgs returns null and prints help for no args", () => {
  assert.equal(parseArgs([]), null);
});
