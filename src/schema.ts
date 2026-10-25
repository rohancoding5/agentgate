import { z } from "zod";

export const SemanticReviewSchema = z.object({
  isManipulative: z.boolean(),
  reasoning: z.string().min(1),
  suggestedSeverity: z.enum(["low", "medium", "high", "critical"]).nullable(),
});
