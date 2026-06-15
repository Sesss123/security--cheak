export interface ChallengeAnalysis {
  likelyCategory: string;
  confidenceScore: number;
  hints: string[];
  recommendedInvestigationPath: string[];
  learningReferences: string[];
}
