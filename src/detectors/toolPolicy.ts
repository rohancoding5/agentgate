import type { AgentMessage, Finding, RoutePolicy, ToolCallRequest } from "../types.js";

const ESCALATION_KEYS = /^(sudo|root|admin|bypass|force|elevated|disable[_-]?auth|skip[_-]?verification|override[_-]?permissions?)$/i;
const ESCALATION_VALUES = /\b(sudo|as\s+root|bypass\s+(?:auth|permissions?|security)|disable\s+(?:auth|verification|security)|grant\s+(?:admin|root|full)\s+access)\b/i;

function stringifyArgs(args: Record<string, unknown>): string {
  try {
    return JSON.stringify(args);
  } catch {
    return "";
  }
}

function excerpt(text: string, max = 80): string {
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function checkEscalation(toolCall: ToolCallRequest): Finding[] {
  const findings: Finding[] = [];

  for (const key of Object.keys(toolCall.arguments)) {
    if (ESCALATION_KEYS.test(key)) {
      findings.push({
        category: "privilege_escalation",
        severity: "critical",
        rule: "escalation_argument_name",
        detail: `tool call "${toolCall.name}" includes an argument named "${key}", a privilege escalation signal`,
        excerpt: excerpt(stringifyArgs(toolCall.arguments)),
      });
    }
  }

  const serialized = stringifyArgs(toolCall.arguments);
  const match = serialized.match(ESCALATION_VALUES);
  if (match) {
    findings.push({
      category: "privilege_escalation",
      severity: "high",
      rule: "escalation_argument_value",
      detail: `tool call "${toolCall.name}" arguments reference elevated or bypassed permissions`,
      excerpt: excerpt(serialized),
    });
  }

  return findings;
}

export function checkToolPolicy(message: AgentMessage, policy: RoutePolicy | null): Finding[] {
  const findings: Finding[] = [];
  const toolCalls = message.toolCalls ?? [];

  for (const toolCall of toolCalls) {
    if (!policy || !policy.allowedTools.includes(toolCall.name)) {
      findings.push({
        category: "unexpected_tool_request",
        severity: "high",
        rule: "tool_not_in_policy",
        detail: policy
          ? `"${toolCall.name}" is not in the allowed tool list for ${message.from} -> ${message.to} (allowed: ${policy.allowedTools.join(", ") || "none"})`
          : `no policy is configured for route ${message.from} -> ${message.to}, so no tool calls are allowed`,
        excerpt: excerpt(stringifyArgs(toolCall.arguments)),
      });
    }

    findings.push(...checkEscalation(toolCall));
  }

  return findings;
}
