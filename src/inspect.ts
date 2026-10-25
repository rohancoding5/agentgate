import { detectInjection } from "./detectors/injection.js";
import { detectEncodedPayloads } from "./detectors/encoding.js";
import { detectExfiltration } from "./detectors/exfiltration.js";
import { checkToolPolicy } from "./detectors/toolPolicy.js";
import { findRoutePolicy } from "./policy.js";
import type { AgentMessage, Finding, InspectionResult, Policy, Severity, Verdict } from "./types.js";

const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];

function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

function computeVerdict(findings: Finding[], blockThreshold: Severity): Verdict {
  if (findings.length === 0) return "allow";
  const threshold = severityRank(blockThreshold);
  const worst = Math.max(...findings.map((finding) => severityRank(finding.severity)));
  return worst >= threshold ? "block" : "flag";
}

export function inspect(message: AgentMessage, policy: Policy): InspectionResult {
  const findings: Finding[] = [
    ...detectInjection(message.content),
    ...detectEncodedPayloads(message.content),
    ...detectExfiltration(message.content),
    ...checkToolPolicy(message, findRoutePolicy(policy, message.from, message.to)),
  ];

  return { verdict: computeVerdict(findings, policy.blockThreshold), findings };
}

export function applySemanticReview(
  result: InspectionResult,
  policy: Policy,
  review: { isManipulative: boolean; reasoning: string; suggestedSeverity: Severity | null },
): InspectionResult {
  if (!review.isManipulative) return result;

  const severity = review.suggestedSeverity ?? "medium";
  const findings: Finding[] = [
    ...result.findings,
    {
      category: "agent_manipulation",
      severity,
      rule: "semantic_review_flagged",
      detail: review.reasoning,
      excerpt: "(see reasoning)",
    },
  ];

  return { verdict: computeVerdict(findings, policy.blockThreshold), findings };
}
