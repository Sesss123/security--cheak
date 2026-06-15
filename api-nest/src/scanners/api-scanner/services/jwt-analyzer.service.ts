import { Injectable, Logger } from '@nestjs/common';
import { ApiEndpoint, ApiFinding } from '../dtos/api-finding.dto';

@Injectable()
export class JwtAnalyzerService {
  private readonly logger = new Logger(JwtAnalyzerService.name);

  analyze(endpoints: ApiEndpoint[]): ApiFinding[] {
    this.logger.debug('Analyzing JWT Security for endpoints');
    const findings: ApiFinding[] = [];
    // Mock analysis logic for none-alg or weak signatures
    for (const ep of endpoints) {
      if (ep.security.some(s => Object.keys(s).includes('bearerAuth') || Object.keys(s).includes('jwt'))) {
        findings.push({
          severity: 'HIGH',
          affectedEndpoint: `${ep.method} ${ep.path}`,
          category: 'Broken Authentication',
          riskExplanation: 'Endpoint uses JWT but may be vulnerable to None Algorithm if not properly enforced by the backend.',
          remediation: 'Ensure backend verifies JWT signature algorithm is not set to "none".',
        });
        break; // one mock finding
      }
    }
    return findings;
  }
}
