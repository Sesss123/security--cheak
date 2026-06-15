// ── Auth ──────────────────────────────────────────────────────
export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'user';
  created_at: string;
}

export interface AuthPayload {
  userId: string;
  email: string;
  role: string;
}

// ── Scan ──────────────────────────────────────────────────────
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';

export type ScanType =
  | 'port_scan'
  | 'ssl_analysis'
  | 'http_headers'
  | 'security_headers'
  | 'sql_injection'
  | 'xss'
  | 'cors_check'
  | 'info_disclosure'
  | 'jwt_analysis'
  | 'open_redirect';

export interface ScanOptions {
  rate_limit: number;
  timeout_secs: number;
  follow_redirects: boolean;
  max_depth: number;
  port_range: 'Common' | 'Extended' | 'Full';
}

export interface CreateScanRequest {
  target_url: string;
  scan_types: ScanType[];
  options?: Partial<ScanOptions>;
}

export interface Scan {
  id: string;
  user_id: string;
  target_url: string;
  status: ScanStatus;
  scan_types: ScanType[];
  options: ScanOptions;
  started_at: string | null;
  completed_at: string | null;
  risk_score: number | null;
  total_vulns: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message: string | null;
  created_at: string;
}

// ── Vulnerability ─────────────────────────────────────────────
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Vulnerability {
  id: string;
  scan_id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  cvss_score: number;
  cvss_vector: string | null;
  affected_url: string;
  affected_parameter: string | null;
  owasp_category: string | null;
  cwe_id: number | null;
  evidence: Evidence[];
  remediation: string;
  references: string[];
  cve_id?: string;
  exploit_available?: boolean;
  // AI enrichment
  ai_explanation: string | null;
  ai_business_impact: string | null;
  ai_remediation_steps: string[];
  ai_code_example: string | null;
  fix_priority: number | null;
  created_at: string;
}

export interface Evidence {
  evidence_type: string;
  request?: string;
  response?: string;
  payload?: string;
  description: string;
}

// ── WebSocket Events ──────────────────────────────────────────
export type WsEventType =
  | 'scan:started'
  | 'scan:progress'
  | 'scan:vuln_found'
  | 'scan:completed'
  | 'scan:failed';

export interface WsEvent {
  type: WsEventType;
  scan_id: string;
  data: unknown;
  timestamp: string;
}

// ── AI Analysis ───────────────────────────────────────────────
export interface AiVulnAnalysis {
  explanation: string;
  business_impact: string;
  remediation_steps: string[];
  code_example: string | null;
  fix_priority: number;
  attack_path?: string[];
  attack_probability?: string;
}

export interface AiReportSummary {
  executive_summary: string;
  risk_rating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'MINIMAL';
  top_recommendations: string[];
}
