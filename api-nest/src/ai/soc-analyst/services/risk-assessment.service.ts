import { Injectable, Logger } from '@nestjs/common';
import { Vulnerability } from '../../../types';

@Injectable()
export class RiskAssessmentService {
  private readonly logger = new Logger(RiskAssessmentService.name);

  assessRisk(vuln: Vulnerability): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
    this.logger.debug(`Assessing risk for ${vuln.title}`);
    // A sophisticated model would combine CVSS, AI insights, and Threat Intel
    if (vuln.exploit_available || vuln.cvss_score >= 9.0) return 'CRITICAL';
    if (vuln.cvss_score >= 7.0) return 'HIGH';
    if (vuln.cvss_score >= 4.0) return 'MEDIUM';
    if (vuln.cvss_score > 0) return 'LOW';
    return 'INFO';
  }
}
