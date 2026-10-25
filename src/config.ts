export type Command =
  | { command: "inspect"; file: string | null; policyPath: string | null; semantic: boolean; json: boolean }
  | { command: "serve"; port: number; policyPath: string | null; targetsPath: string; semantic: boolean };

function printHelp(): void {
  console.log(`agentgate inspect <file> [options]
agentgate serve --targets <file> [options]

a security layer that sits between AI agents and inspects every message for
prompt injection, data exfiltration, unexpected tool requests, privilege
escalation, suspicious encoded payloads, and attempts to manipulate another
agent, so the agents don't have to trust each other.

  inspect <file>        run every check against one message (JSON file with
                        from, to, content, and optional toolCalls) and print
                        a verdict and findings. omit <file> to read from stdin
  serve                  run a real HTTP relay: agents POST a message to
                        /relay, it gets inspected, and only allowed or
                        flagged messages get forwarded to the real target
  --policy <path>        JSON policy file (routes with allowedTools, and a
                        blockThreshold). without one, every tool call is
                        denied by default and only text-based checks run
  --targets <path>        serve only, required. JSON object mapping agent
                        name to the real URL to relay allowed messages to
  --port <n>              serve only, port to listen on (default 8787)
  --semantic              also ask Claude to review anything the rule-based
                        checks didn't already block, needs ANTHROPIC_API_KEY
  --json                  inspect only, print machine-readable JSON
  --help                  show this message

examples:
  agentgate inspect message.json --policy policy.json
  echo '{"from":"a","to":"b","content":"hi"}' | agentgate inspect
  agentgate serve --policy policy.json --targets targets.json --port 8787
`);
}

export function parseArgs(argv: string[]): Command | null {
  if (argv.length === 0 || argv.includes("--help")) {
    printHelp();
    return null;
  }

  const [first, ...rest] = argv;

  function next(flag: string, i: number, list: string[]): string {
    const value = list[i + 1];
    if (value === undefined) throw new Error(`${flag} needs a value`);
    return value;
  }

  if (first === "inspect") {
    let file: string | null = null;
    let policyPath: string | null = null;
    let semantic = false;
    let json = false;

    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i];
      if (arg === "--policy") {
        policyPath = next(arg, i, rest);
        i += 1;
      } else if (arg === "--semantic") {
        semantic = true;
      } else if (arg === "--json") {
        json = true;
      } else if (arg.startsWith("--")) {
        throw new Error(`unknown flag "${arg}"`);
      } else if (file === null) {
        file = arg;
      }
    }

    return { command: "inspect", file, policyPath, semantic, json };
  }

  if (first === "serve") {
    let port = 8787;
    let policyPath: string | null = null;
    let targetsPath: string | null = null;
    let semantic = false;

    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i];
      if (arg === "--port") {
        const value = Number(next(arg, i, rest));
        if (!Number.isInteger(value) || value <= 0) throw new Error("--port must be a positive integer");
        port = value;
        i += 1;
      } else if (arg === "--policy") {
        policyPath = next(arg, i, rest);
        i += 1;
      } else if (arg === "--targets") {
        targetsPath = next(arg, i, rest);
        i += 1;
      } else if (arg === "--semantic") {
        semantic = true;
      } else if (arg.startsWith("--")) {
        throw new Error(`unknown flag "${arg}"`);
      }
    }

    if (!targetsPath) throw new Error("serve needs --targets, a JSON file mapping agent name to a real URL");
    return { command: "serve", port, policyPath, targetsPath, semantic };
  }

  throw new Error(`unknown command "${first}", use "inspect" or "serve"`);
}
