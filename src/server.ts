import { createServer as createHttpServer, type IncomingMessage, type ServerResponse, type Server } from "http";
import { inspect, applySemanticReview } from "./inspect.js";
import { semanticReview, isSemanticReviewAvailable } from "./semanticReview.js";
import type { AgentMessage, Policy } from "./types.js";

export type FirewallServerOptions = {
  policy: Policy;
  targets: Record<string, string>;
  useSemanticReview?: boolean;
  onLog?: (line: string) => void;
};

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(payload);
}

function parseMessage(raw: string): AgentMessage | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.from !== "string" || typeof obj.to !== "string" || typeof obj.content !== "string") return null;
  return {
    from: obj.from,
    to: obj.to,
    content: obj.content,
    toolCalls: Array.isArray(obj.toolCalls) ? (obj.toolCalls as AgentMessage["toolCalls"]) : undefined,
  };
}

export function createServer(options: FirewallServerOptions): Server {
  const log = options.onLog ?? (() => {});

  return createHttpServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/health") {
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method !== "POST" || req.url !== "/relay") {
      sendJson(res, 404, { error: "not found, POST a message to /relay" });
      return;
    }

    const raw = await readBody(req);
    const message = parseMessage(raw);
    if (!message) {
      sendJson(res, 400, { error: "body must be JSON with string from, to, content" });
      return;
    }

    let result = inspect(message, options.policy);

    if (result.verdict !== "block" && options.useSemanticReview && isSemanticReviewAvailable()) {
      try {
        const review = await semanticReview(message);
        result = applySemanticReview(result, options.policy, review);
      } catch (err) {
        log(`semantic review failed, continuing on rule-based verdict alone: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    log(`${message.from} -> ${message.to}: ${result.verdict} (${result.findings.length} finding(s))`);

    if (result.verdict === "block") {
      sendJson(res, 403, { verdict: result.verdict, findings: result.findings });
      return;
    }

    const targetUrl = options.targets[message.to];
    if (!targetUrl) {
      sendJson(res, 502, { error: `no target configured for agent "${message.to}"`, verdict: result.verdict, findings: result.findings });
      return;
    }

    try {
      const upstream = await fetch(targetUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agentgate-verdict": result.verdict,
          "x-agentgate-findings": String(result.findings.length),
        },
        body: JSON.stringify(message),
      });
      const upstreamBody = await upstream.text();
      res.writeHead(upstream.status, {
        "content-type": upstream.headers.get("content-type") ?? "application/json",
        "x-agentgate-verdict": result.verdict,
      });
      res.end(upstreamBody);
    } catch (err) {
      sendJson(res, 502, { error: `failed to relay to ${message.to}: ${err instanceof Error ? err.message : String(err)}` });
    }
  });
}
