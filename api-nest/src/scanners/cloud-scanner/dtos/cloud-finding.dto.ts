export interface CloudFinding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  platform: 'AWS' | 'Azure' | 'GCP';
  serviceName: string;
  assetId: string;
  issueType: string;
  description: string;
  remediation: string;
  complianceViolations?: string[];
}

export interface CloudReport {
  targetAccount: string;
  findings: CloudFinding[];
  riskScore: number;
}
