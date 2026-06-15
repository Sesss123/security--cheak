import { Injectable, Logger } from '@nestjs/common';
import { Vulnerability } from '../../../types';

@Injectable()
export class MitigationPlannerService {
  private readonly logger = new Logger(MitigationPlannerService.name);

  planMitigation(vuln: Vulnerability): string[] {
    this.logger.debug(`Planning mitigation for ${vuln.title}`);
    const plan: string[] = [];
    
    if (vuln.remediation) {
      plan.push(vuln.remediation);
    } else {
      plan.push('Investigate root cause and apply vendor patches if applicable.');
    }

    if (vuln.category.includes('Injection')) {
      plan.push('Implement Parameterized Queries (Prepared Statements).');
      plan.push('Deploy or configure Web Application Firewall (WAF) rules.');
    }

    if (plan.length === 1) {
       plan.push('Review access logs for signs of active exploitation.');
    }

    return plan;
  }
}
