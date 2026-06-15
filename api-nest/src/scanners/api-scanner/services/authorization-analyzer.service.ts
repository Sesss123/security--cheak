import { Injectable, Logger } from '@nestjs/common';
import { ApiEndpoint, ApiFinding } from '../dtos/api-finding.dto';

@Injectable()
export class AuthorizationAnalyzerService {
  private readonly logger = new Logger(AuthorizationAnalyzerService.name);

  analyze(endpoints: ApiEndpoint[]): ApiFinding[] {
    this.logger.debug('Analyzing Authorization requirements');
    const findings: ApiFinding[] = [];
    
    for (const ep of endpoints) {
      if (ep.security.length === 0 && (ep.method === 'POST' || ep.method === 'PUT' || ep.method === 'DELETE' || ep.path.includes('admin'))) {
        findings.push({
          severity: 'CRITICAL',
          affectedEndpoint: `${ep.method} ${ep.path}`,
          category: 'Missing Authorization',
          riskExplanation: 'A state-changing or sensitive endpoint does not define any security schemes.',
          remediation: 'Implement authentication and role-based access control (RBAC).',
        });
      }
    }
    return findings;
  }
}
