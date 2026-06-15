import { Injectable, Logger } from '@nestjs/common';
import { Vulnerability } from '../../../types';

@Injectable()
export class ExecutiveSummaryGenerator {
  private readonly logger = new Logger(ExecutiveSummaryGenerator.name);

  generateSummary(vuln: Vulnerability, riskLevel: string, impacts: string[]): string {
    this.logger.debug(`Generating executive summary for ${vuln.title}`);
    return `A ${riskLevel} severity vulnerability identified as ${vuln.title} was found affecting ${vuln.affected_url}. If exploited, this could lead to ${impacts.join(' and ').toLowerCase()}. Immediate review and remediation are recommended.`;
  }
}
