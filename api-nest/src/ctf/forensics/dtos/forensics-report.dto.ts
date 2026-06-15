export interface ForensicsReport {
  fileName: string;
  metadata: Record<string, any>;
  iocs: string[];
  timeline: any[];
  artifacts: string[];
  evidenceSummary: string;
}
