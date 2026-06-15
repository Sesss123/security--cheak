import { Injectable, Logger } from '@nestjs/common';
import { ContainerFinding } from '../dtos/container-finding.dto';
import { Vulnerability } from '../../../types';
import { randomUUID } from 'crypto';

@Injectable()
export class ContainerRiskScorer {
  private readonly logger = new Logger(ContainerRiskScorer.name);

  scoreAndMap(scanId: string, target: string, findings: ContainerFinding[]): Vulnerability[] {
    this.logger.debug(`Scoring ${findings.length} container findings`);
    
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
        category: 'Container Security',
        cvss_score: cvssScore,
        cvss_vector: null,
        affected_url: target,
        affected_parameter: f.component,
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
