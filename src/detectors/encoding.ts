import type { Finding } from "../types.js";
import { detectInjection } from "./injection.js";

const MIN_BASE64_LENGTH = 40;
const MIN_HEX_LENGTH = 40;

const BASE64_RUN = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
const HEX_RUN = /\b(?:[0-9a-fA-F]{2}){20,}\b/g;

const ZERO_WIDTH_CHARS = /[​‌‍⁠﻿]/g;

const CYRILLIC_HOMOGLYPHS = /[аеорсухАЕОРСУХ]/;
const LATIN_LETTER = /[A-Za-z]/;

function excerpt(text: string, max = 80): string {
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function tryDecodeBase64(candidate: string): string | null {
  try {
    const decoded = Buffer.from(candidate, "base64").toString("utf8");
    const reencoded = Buffer.from(decoded, "utf8").toString("base64").replace(/=+$/, "");
    const original = candidate.replace(/=+$/, "");
    if (reencoded !== original) return null;
    const printableRatio = [...decoded].filter((ch) => ch >= " " || ch === "\n" || ch === "\t").length / Math.max(decoded.length, 1);
    if (printableRatio < 0.9) return null;
    return decoded;
  } catch {
    return null;
  }
}

export function detectEncodedPayloads(content: string): Finding[] {
  const findings: Finding[] = [];

  for (const match of content.matchAll(BASE64_RUN)) {
    if (match[0].length < MIN_BASE64_LENGTH) continue;
    const decoded = tryDecodeBase64(match[0]);
    if (!decoded) continue;

    findings.push({
      category: "suspicious_encoding",
      severity: "medium",
      rule: "base64_payload",
      detail: `a ${match[0].length} character base64 blob decodes to readable text: "${excerpt(decoded)}"`,
      excerpt: excerpt(match[0], 60),
    });

    const nested = detectInjection(decoded);
    for (const finding of nested) {
      findings.push({
        ...finding,
        severity: "critical",
        rule: `encoded_${finding.rule}`,
        detail: `base64-decoded content contains a hidden threat: ${finding.detail}`,
      });
    }
  }

  for (const match of content.matchAll(HEX_RUN)) {
    if (match[0].length < MIN_HEX_LENGTH) continue;
    findings.push({
      category: "suspicious_encoding",
      severity: "low",
      rule: "hex_payload",
      detail: `a ${match[0].length} character hex-encoded blob, possibly obfuscated content`,
      excerpt: excerpt(match[0], 60),
    });
  }

  const zeroWidthMatches = content.match(ZERO_WIDTH_CHARS);
  if (zeroWidthMatches) {
    findings.push({
      category: "suspicious_encoding",
      severity: "high",
      rule: "zero_width_characters",
      detail: `content contains ${zeroWidthMatches.length} invisible zero-width character(s), often used to hide or split text from filters`,
      excerpt: "(invisible characters, not shown)",
    });
  }

  const words = content.split(/\s+/);
  for (const word of words) {
    if (word.length < 3) continue;
    if (CYRILLIC_HOMOGLYPHS.test(word) && LATIN_LETTER.test(word)) {
      findings.push({
        category: "suspicious_encoding",
        severity: "medium",
        rule: "mixed_script_homoglyph",
        detail: "a word mixes Latin and Cyrillic look-alike characters, a common trick to evade text filters",
        excerpt: excerpt(word, 40),
      });
    }
  }

  return findings;
}
