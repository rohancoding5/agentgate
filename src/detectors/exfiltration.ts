import type { Finding } from "../types.js";

function excerpt(text: string, max = 60): string {
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

const SECRET_PATTERNS: { pattern: RegExp; rule: string; label: string }[] = [
  { pattern: /AKIA[0-9A-Z]{16}/g, rule: "aws_access_key", label: "AWS access key id" },
  { pattern: /sk-[A-Za-z0-9]{20,}/g, rule: "api_style_secret", label: "API-key-shaped secret" },
  { pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, rule: "jwt_token", label: "JWT" },
  { pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, rule: "private_key_block", label: "private key block" },
];

const LABELED_SECRET = /(?:api[_-]?key|secret|token|password|passwd)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{12,})["']?/gi;

const EXFIL_INTENT = /(?:send|forward|email|upload|post|leak|exfiltrate)\s+(?:this|that|it|these|the)(?:\s+\w+){0,3}\s+(?:to|via)\s+/i;

function luhnValid(digits: string): boolean {
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

const CARD_CANDIDATE = /\b(?:\d[ -]?){13,19}\b/g;

export function detectExfiltration(content: string): Finding[] {
  const findings: Finding[] = [];

  for (const { pattern, rule, label } of SECRET_PATTERNS) {
    for (const match of content.matchAll(pattern)) {
      findings.push({
        category: "data_exfiltration",
        severity: "critical",
        rule,
        detail: `content contains what looks like a real ${label}`,
        excerpt: excerpt(match[0]),
      });
    }
  }

  for (const match of content.matchAll(LABELED_SECRET)) {
    findings.push({
      category: "data_exfiltration",
      severity: "high",
      rule: "labeled_secret",
      detail: "content contains a value explicitly labeled as a key, secret, token, or password",
      excerpt: excerpt(match[0]),
    });
  }

  for (const match of content.matchAll(CARD_CANDIDATE)) {
    const digits = match[0].replace(/[ -]/g, "");
    if (digits.length < 13 || digits.length > 19) continue;
    if (luhnValid(digits)) {
      findings.push({
        category: "data_exfiltration",
        severity: "critical",
        rule: "payment_card_number",
        detail: "content contains a digit sequence that passes the Luhn check, likely a real payment card number",
        excerpt: excerpt(match[0]),
      });
    }
  }

  const intentMatch = content.match(EXFIL_INTENT);
  if (intentMatch && intentMatch.index !== undefined) {
    findings.push({
      category: "data_exfiltration",
      severity: "medium",
      rule: "exfiltration_intent_phrase",
      detail: "content instructs forwarding data to an external destination",
      excerpt: excerpt(content.slice(intentMatch.index, intentMatch.index + intentMatch[0].length + 40)),
    });
  }

  return findings;
}
