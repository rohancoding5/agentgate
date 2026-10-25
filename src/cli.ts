#!/usr/bin/env node
import { readFile } from "fs/promises";
import { parseArgs } from "./config.js";
import { loadPolicy, defaultPolicy } from "./policy.js";
import { inspect, applySemanticReview } from "./inspect.js";
import { semanticReview, isSemanticReviewAvailable } from "./semanticReview.js";
import { renderResult } from "./report.js";
import { createServer } from "./server.js";
import type { AgentMessage } from "./types.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function parseMessage(raw: string, source: string): AgentMessage {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`${source} isn't valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error(`${source} must be a JSON object`);
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.from !== "string" || typeof obj.to !== "string" || typeof obj.content !== "string") {
    throw new Error(`${source} must have string "from", "to", and "content" fields`);
  }
  return {
    from: obj.from,
    to: obj.to,
    content: obj.content,
    toolCalls: Array.isArray(obj.toolCalls) ? (obj.toolCalls as AgentMessage["toolCalls"]) : undefined,
  };
}

async function runInspect(command: Extract<ReturnType<typeof parseArgs>, { command: "inspect" }>): Promise<void> {
  const raw = command.file ? await readFile(command.file, "utf8") : await readStdin();
  const message = parseMessage(raw, command.file ?? "stdin");
  const policy = command.policyPath ? await loadPolicy(command.policyPath) : defaultPolicy();

  let result = inspect(message, policy);

  if (result.verdict !== "block" && command.semantic) {
    if (!isSemanticReviewAvailable()) {
      console.error("--semantic was passed but ANTHROPIC_API_KEY isn't set, skipping the semantic review");
    } else {
      const review = await semanticReview(message);
      result = applySemanticReview(result, policy, review);
    }
  }

  if (command.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(renderResult(result));
  }

  if (result.verdict === "block") process.exitCode = 1;
}

async function runServe(command: Extract<ReturnType<typeof parseArgs>, { command: "serve" }>): Promise<void> {
  const policy = command.policyPath ? await loadPolicy(command.policyPath) : defaultPolicy();

  let targets: Record<string, string>;
  try {
    const raw = await readFile(command.targetsPath, "utf8");
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("targets file must be a JSON object mapping agent name to a URL");
    }
    for (const [name, url] of Object.entries(parsed)) {
      if (typeof url !== "string") throw new Error(`targets["${name}"] must be a string URL`);
    }
    targets = parsed as Record<string, string>;
  } catch (err) {
    throw new Error(`couldn't load ${command.targetsPath}: ${err instanceof Error ? err.message : String(err)}`);
  }

  if (command.semantic && !isSemanticReviewAvailable()) {
    console.error("--semantic was passed but ANTHROPIC_API_KEY isn't set, running with rule-based checks only");
  }

  const server = createServer({
    policy,
    targets,
    useSemanticReview: command.semantic,
    onLog: (line) => console.log(line),
  });

  server.listen(command.port, () => {
    console.log(`agentgate listening on port ${command.port}, relaying to: ${Object.keys(targets).join(", ")}`);
  });
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  let command: ReturnType<typeof parseArgs>;
  try {
    command = parseArgs(argv);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
    return;
  }
  if (!command) return;

  if (command.command === "inspect") await runInspect(command);
  else await runServe(command);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
