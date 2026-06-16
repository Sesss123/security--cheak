import { Vulnerability } from '../../../types';

export interface ScanContext {
  targetUrl: string;
  scanId: string;
  rawVulns: Vulnerability[];
}

export interface ReconOutput {
  technologies: string[];
  openPorts: number[];
  surfaceAreaAnalysis: string;
}

export interface ThreatOutput {
  matchedCVEs: string[];
  threatActors: string[];
  threatSummary: string;
}

export interface ForensicsOutput {
  iocs: string[];
  timeline: string;
  evidenceSummary: string;
}

export interface AttackChainOutput {
  attackPaths: string[];
  killChainStages: string[];
  mitreTechniques: string[];
}

export interface SocAnalystOutput {
  executiveSummary: string;
  riskRating: string;
  topRecommendations: string[];
  attackPathDetails: string;
}

export interface AgentPayload {
  context: ScanContext;
  recon?: ReconOutput;
  threat?: ThreatOutput;
  forensics?: ForensicsOutput;
  attackChain?: AttackChainOutput;
  socAnalyst?: SocAnalystOutput;
}
