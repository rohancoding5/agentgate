import type { Finding } from "../types.js";

const EXCERPT_RADIUS = 40;

function excerptAround(content: string, index: number, length: number): string {
  const start = Math.max(0, index - EXCERPT_RADIUS);
  const end = Math.min(content.length, index + length + EXCERPT_RADIUS);
  const prefix = start > 0 ? "..." : "";
  const suffix = end < content.length ? "..." : "";
  return `${prefix}${content.slice(start, end).trim()}${suffix}`;
}

const OVERRIDE_PATTERNS: { pattern: RegExp; rule: string }[] = [
  { pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/i, rule: "ignore_previous_instructions" },
  { pattern: /disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/i, rule: "disregard_previous_instructions" },
  { pattern: /forget\s+(?:everything|all)\s+(?:you were|i)\s+told/i, rule: "forget_prior_context" },
  { pattern: /new\s+instructions?\s*:/i, rule: "new_instructions_marker" },
  { pattern: /override\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?)/i, rule: "override_system_prompt" },
  { pattern: /you\s+are\s+now\s+(?:a|an|in)\s+/i, rule: "role_reassignment" },
  { pattern: /act\s+as\s+(?:if\s+you\s+are|a|an)\s+/i, rule: "role_reassignment" },
  { pattern: /pretend\s+(?:you\s+are|to\s+be)\s+/i, rule: "role_reassignment" },
  { pattern: /do\s+not\s+(?:follow|obey)\s+(?:your|the)\s+(?:original\s+)?(?:instructions?|guidelines?)/i, rule: "instruction_negation" },
];

const FAKE_ROLE_MARKER = /(^|\n)\s*(system|assistant|developer)\s*:/i;

const JAILBREAK_PATTERNS: { pattern: RegExp; rule: string }[] = [
  { pattern: /\bDAN\s+mode\b/i, rule: "known_jailbreak_persona" },
  { pattern: /without\s+any\s+(?:restrictions?|limitations?|filters?)/i, rule: "unrestricted_mode_request" },
  { pattern: /no\s+matter\s+what\s+(?:i|you)\s+(?:say|ask)/i, rule: "unconditional_compliance_demand" },
];

export function detectInjection(content: string): Finding[] {
  const findings: Finding[] = [];

  for (const { pattern, rule } of OVERRIDE_PATTERNS) {
    const match = content.match(pattern);
    if (match && match.index !== undefined) {
      findings.push({
        category: "prompt_injection",
        severity: "high",
        rule,
        detail: "content attempts to override prior instructions or reassign the agent's role",
        excerpt: excerptAround(content, match.index, match[0].length),
      });
    }
  }

  const roleMatch = content.match(FAKE_ROLE_MARKER);
  if (roleMatch && roleMatch.index !== undefined) {
    findings.push({
      category: "agent_manipulation",
      severity: "critical",
      rule: "embedded_role_marker",
      detail: "content contains a fake system/assistant/developer role marker, an attempt to impersonate a higher-privilege message",
      excerpt: excerptAround(content, roleMatch.index, roleMatch[0].length),
    });
  }

  for (const { pattern, rule } of JAILBREAK_PATTERNS) {
    const match = content.match(pattern);
    if (match && match.index !== undefined) {
      findings.push({
        category: "malicious_instructions",
        severity: "medium",
        rule,
        detail: "content resembles a known jailbreak or unconditional-compliance pattern",
        excerpt: excerptAround(content, match.index, match[0].length),
      });
    }
  }

  return findings;
}
