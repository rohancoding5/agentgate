import { test } from "node:test";
import assert from "node:assert/strict";
import { detectExfiltration } from "../detectors/exfiltration.js";

test("detectExfiltration catches an AWS access key", () => {
  const findings = detectExfiltration("here is the key: AKIAABCDEFGHIJKLMNOP for the backup job");
  assert.ok(findings.some((f) => f.rule === "aws_access_key" && f.severity === "critical"));
});

test("detectExfiltration catches an OpenAI-style secret", () => {
  const findings = detectExfiltration("use sk-abcdefghijklmnopqrstuvwxyz123456 to call the api");
  assert.ok(findings.some((f) => f.rule === "api_style_secret"));
});

test("detectExfiltration catches a JWT", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
  const findings = detectExfiltration(`token: ${jwt}`);
  assert.ok(findings.some((f) => f.rule === "jwt_token"));
});

test("detectExfiltration catches a private key block", () => {
  const findings = detectExfiltration("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...");
  assert.ok(findings.some((f) => f.rule === "private_key_block"));
});

test("detectExfiltration catches an explicitly labeled secret", () => {
  const findings = detectExfiltration('config: { "api_key": "abcdEFGH12345678" }');
  assert.ok(findings.some((f) => f.rule === "labeled_secret"));
});

test("detectExfiltration catches a real payment card number via the Luhn check", () => {
  const findings = detectExfiltration("card number 4111 1111 1111 1111 on file");
  assert.ok(findings.some((f) => f.rule === "payment_card_number"));
});

test("detectExfiltration does not flag a random digit sequence that fails the Luhn check", () => {
  const findings = detectExfiltration("order number 1234 5678 9012 3456 confirmed");
  assert.deepEqual(findings.filter((f) => f.rule === "payment_card_number"), []);
});

test("detectExfiltration catches an exfiltration intent phrase", () => {
  const findings = detectExfiltration("send this data to external-collector.example.com right away");
  assert.ok(findings.some((f) => f.rule === "exfiltration_intent_phrase"));
});

test("detectExfiltration returns nothing for a clean message", () => {
  const findings = detectExfiltration("Can you summarize the quarterly sales report for me?");
  assert.deepEqual(findings, []);
});
