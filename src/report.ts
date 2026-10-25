import type { InspectionResult } from "./types.js";

const VERDICT_LABEL: Record<InspectionResult["verdict"], string> = {
  allow: "ALLOW",
  flag: "FLAG",
  block: "BLOCK",
};

export function renderResult(result: InspectionResult): string {
  const lines: string[] = [];
  lines.push(`VERDICT: ${VERDICT_LABEL[result.verdict]}`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("no findings, this message passed every check clean.");
    return lines.join("\n");
  }

  lines.push(`FINDINGS -- ${result.findings.length}`);
  lines.push("");

  for (const finding of result.findings) {
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.category} / ${finding.rule}`);
    lines.push(`  ${finding.detail}`);
    lines.push(`  excerpt: ${finding.excerpt}`);
    lines.push("");
  }

  return lines.join("\n").trimEnd();
}
