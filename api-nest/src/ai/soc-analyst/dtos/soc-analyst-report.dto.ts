export interface SocAnalystReport {
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  affectedAssets: string[];
  attackProbability: 'HIGH' | 'MEDIUM' | 'LOW';
  businessImpact: string[];
  threatIntelligence: {
    relatedCwe?: string;
    relatedCve?: string;
    exploitAvailable?: boolean;
  };
  recommendedFix: string[];
  executiveSummary: string;
}
