import { readFile } from "fs/promises";
import type { Policy, RoutePolicy, Severity } from "./types.js";

const VALID_SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

export function validatePolicy(raw: unknown): Policy {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("policy must be a JSON object");
  }

  const obj = raw as Record<string, unknown>;

  if (!Array.isArray(obj.routes)) {
    throw new Error('policy needs a "routes" array');
  }

  const routes: RoutePolicy[] = obj.routes.map((entry, index) => {
    if (typeof entry !== "object" || entry === null) {
      throw new Error(`routes[${index}] must be an object`);
    }
    const route = entry as Record<string, unknown>;
    if (typeof route.from !== "string" || !route.from) {
      throw new Error(`routes[${index}].from must be a non-empty string`);
    }
    if (typeof route.to !== "string" || !route.to) {
      throw new Error(`routes[${index}].to must be a non-empty string`);
    }
    if (!Array.isArray(route.allowedTools) || !route.allowedTools.every((tool) => typeof tool === "string")) {
      throw new Error(`routes[${index}].allowedTools must be an array of strings`);
    }
    return { from: route.from, to: route.to, allowedTools: route.allowedTools as string[] };
  });

  const blockThreshold = obj.blockThreshold ?? "high";
  if (typeof blockThreshold !== "string" || !VALID_SEVERITIES.includes(blockThreshold as Severity)) {
    throw new Error(`blockThreshold must be one of ${VALID_SEVERITIES.join(", ")}`);
  }

  return { routes, blockThreshold: blockThreshold as Severity };
}

export function findRoutePolicy(policy: Policy, from: string, to: string): RoutePolicy | null {
  return policy.routes.find((route) => route.from === from && route.to === to) ?? null;
}

export async function loadPolicy(path: string): Promise<Policy> {
  const raw = await readFile(path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`"${path}" isn't valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  return validatePolicy(parsed);
}

export function defaultPolicy(): Policy {
  return { routes: [], blockThreshold: "high" };
}
