import { Injectable, Logger } from '@nestjs/common';
import { CloudFinding } from '../dtos/cloud-finding.dto';
import { Vulnerability } from '../../../types';
import { randomUUID } from 'crypto';

@Injectable()
export class CloudRiskScoringService {
  private readonly logger = new Logger(CloudRiskScoringService.name);

  scoreAndMap(scanId: string, findings: CloudFinding[]): Vulnerability[] {
    this.logger.debug(`Scoring ${findings.length} cloud findings`);
    
    return findings.map(f => {
      let cvssScore = 5.0;
      if (f.severity === 'CRITICAL') cvssScore = 9.5;
      if (f.severity === 'HIGH') cvssScore = 7.5;
      if (f.severity === 'MEDIUM') cvssScore = 5.5;
      if (f.severity === 'LOW') cvssScore = 3.5;

      return {
        id: randomUUID(),
        scan_id: scanId,
        title: f.issueType,
        description: f.description,
        severity: f.severity,
        category: 'Cloud Security',
        cvss_score: cvssScore,
        cvss_vector: null,
        affected_url: f.assetId,
        affected_parameter: f.serviceName,
        owasp_category: f.complianceViolations ? f.complianceViolations.join(', ') : null,
        cwe_id: null,
        evidence: [],
        remediation: f.remediation,
        references: f.complianceViolations || [],
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
