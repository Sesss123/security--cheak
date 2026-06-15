import { Injectable, Logger } from '@nestjs/common';
import { ApiEndpoint, ApiFinding } from '../dtos/api-finding.dto';

@Injectable()
export class IdorDetectionService {
  private readonly logger = new Logger(IdorDetectionService.name);

  analyze(endpoints: ApiEndpoint[]): ApiFinding[] {
    this.logger.debug('Detecting IDOR patterns');
    const findings: ApiFinding[] = [];
    
    for (const ep of endpoints) {
      if (ep.path.match(/{[a-zA-Z0-9_]+Id}/) && ep.security.length > 0) {
        findings.push({
          severity: 'HIGH',
          affectedEndpoint: `${ep.method} ${ep.path}`,
          category: 'BOLA / IDOR',
          riskExplanation: 'Endpoint accepts an ID parameter. Verify that the backend checks object ownership against the authenticated user.',
          remediation: 'Implement ownership checks at the data access layer for every resource request.',
        });
      }
    }
    return findings;
  }
}
