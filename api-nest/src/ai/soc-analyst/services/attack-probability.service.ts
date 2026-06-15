import { Injectable, Logger } from '@nestjs/common';
import { Vulnerability } from '../../../types';

@Injectable()
export class AttackProbabilityService {
  private readonly logger = new Logger(AttackProbabilityService.name);

  calculateProbability(vuln: Vulnerability): 'HIGH' | 'MEDIUM' | 'LOW' {
    this.logger.debug(`Calculating probability for ${vuln.title}`);
    if (vuln.exploit_available || vuln.category.includes('Injection') || vuln.category.includes('Auth')) {
      return 'HIGH';
    }
    if (vuln.severity === 'MEDIUM') return 'MEDIUM';
    return 'LOW';
  }
}
