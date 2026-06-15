import { Injectable, Logger } from '@nestjs/common';
import { ApiEndpoint, ApiFinding } from '../dtos/api-finding.dto';

@Injectable()
export class RateLimitAnalyzerService {
  private readonly logger = new Logger(RateLimitAnalyzerService.name);

  analyze(endpoints: ApiEndpoint[]): ApiFinding[] {
    this.logger.debug('Detecting Missing Rate Limits');
    const findings: ApiFinding[] = [];
    
    for (const ep of endpoints) {
      if (ep.path.toLowerCase().includes('login') || ep.path.toLowerCase().includes('auth') || ep.path.toLowerCase().includes('password')) {
        findings.push({
          severity: 'MEDIUM',
          affectedEndpoint: `${ep.method} ${ep.path}`,
          category: 'Missing Rate Limiting',
          riskExplanation: 'Authentication endpoints are susceptible to brute-force attacks if rate limiting is not enforced.',
          remediation: 'Implement rate limiting (e.g., 5 requests per minute per IP).',
        });
      }
    }
    return findings;
  }
}
