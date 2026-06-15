export interface ApiEndpoint {
  method: string;
  path: string;
  parameters: any[];
  security: any[];
}

export interface ApiFinding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  affectedEndpoint: string;
  category: string;
  riskExplanation: string;
  remediation: string;
}
