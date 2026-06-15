import { Injectable, Logger } from '@nestjs/common';
import { ApiFinding } from '../dtos/api-finding.dto';
import { Vulnerability } from '../../../types';
import { randomUUID } from 'crypto';

@Injectable()
export class ApiRiskScoringService {
  private readonly logger = new Logger(ApiRiskScoringService.name);

  scoreAndMap(scanId: string, targetUrl: string, findings: ApiFinding[]): Vulnerability[] {
    this.logger.debug(`Scoring ${findings.length} API findings`);
    
    return findings.map(f => {
      let cvssScore = 5.0;
      if (f.severity === 'CRITICAL') cvssScore = 9.5;
      if (f.severity === 'HIGH') cvssScore = 7.5;
      if (f.severity === 'MEDIUM') cvssScore = 5.5;
      if (f.severity === 'LOW') cvssScore = 3.5;

      return {
        id: randomUUID(),
        scan_id: scanId,
        title: f.category,
        description: f.riskExplanation,
        severity: f.severity,
        category: 'API Security',
        cvss_score: cvssScore,
        cvss_vector: null,
        affected_url: `${targetUrl}${f.affectedEndpoint}`,
        affected_parameter: null,
        owasp_category: null,
        cwe_id: null,
        evidence: [],
        remediation: f.remediation,
        references: [],
        ai_explanation: null,
        ai_business_impact: null,
        ai_remediation_steps: [],
        ai_code_example: null,
        fix_priority: null,
        created_at: new Date().toISOString(),
      };
    });
  }
}
