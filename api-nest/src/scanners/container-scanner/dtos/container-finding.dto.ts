export interface ContainerFinding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  component: string; // e.g., Base Image, K8s Manifest, Dockerfile
  issueType: string;
  description: string;
  remediation: string;
}

export interface ContainerReport {
  target: string;
  findings: ContainerFinding[];
  criticalCount: number;
  misconfigurationsCount: number;
}
