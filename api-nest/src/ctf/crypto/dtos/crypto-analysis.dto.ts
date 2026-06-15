export interface CryptoAnalysisResult {
  detectedEncoding: string;
  possibleCipher: string;
  suggestedNextStep: string;
  confidenceScore: number;
}
