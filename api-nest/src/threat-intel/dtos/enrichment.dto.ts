export interface EnrichmentData {
  cveId?: string;
  isCisaKev: boolean;
  exploitAvailable: boolean;
  cvssScore: number;
  threatScore: number;
  threatSummary: string;
}

export interface CveDetail {
  id: string;
  cvssV3Score: number;
  description: string;
  publishedDate: string;
}
