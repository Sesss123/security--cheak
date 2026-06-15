export interface ReAnalysisResult {
  fileName: string;
  architecture: string;
  interestingStrings: string[];
  suspiciousImports: string[];
  highEntropySections: string[];
  potentialFlagLocations: string[];
  summary: string;
}
