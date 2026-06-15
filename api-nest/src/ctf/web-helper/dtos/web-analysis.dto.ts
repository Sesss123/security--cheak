export interface WebAnalysisResult {
  inputType: 'COOKIE' | 'JWT' | 'BASE64' | 'URL' | 'HASH' | 'HTTP';
  decodedData: string;
  securityObservations: string[];
  metadata?: Record<string, any>;
}
