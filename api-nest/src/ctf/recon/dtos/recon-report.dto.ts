export interface ReconFinding {
  type: 'SUBDOMAIN' | 'DNS' | 'TECHNOLOGY' | 'HEADER' | 'JS_FILE' | 'ENDPOINT' | 'ATTACK_SURFACE';
  value: string;
  confidence: number;
  metadata?: Record<string, any>;
}

export interface ReconReport {
  target: string;
  technologies: string[];
  subdomains: string[];
  interestingFiles: string[];
  exposedServices: string[];
  attackSurfaceMap: any;
  findings: ReconFinding[];
}
