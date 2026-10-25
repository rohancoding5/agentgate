export type Severity = "low" | "medium" | "high" | "critical";

export type Category =
  | "prompt_injection"
  | "malicious_instructions"
  | "data_exfiltration"
  | "unexpected_tool_request"
  | "privilege_escalation"
  | "suspicious_encoding"
  | "agent_manipulation";

export type Finding = {
  category: Category;
  severity: Severity;
  rule: string;
  detail: string;
  excerpt: string;
};

export type Verdict = "allow" | "flag" | "block";

export type AgentMessage = {
  from: string;
  to: string;
  content: string;
  toolCalls?: ToolCallRequest[];
};

export type ToolCallRequest = {
  name: string;
  arguments: Record<string, unknown>;
};

export type InspectionResult = {
  verdict: Verdict;
  findings: Finding[];
};

export type RoutePolicy = {
  from: string;
  to: string;
  allowedTools: string[];
};

export type Policy = {
  routes: RoutePolicy[];
  blockThreshold: Severity;
};

export type SemanticReview = {
  isManipulative: boolean;
  reasoning: string;
  suggestedSeverity: Severity | null;
};
