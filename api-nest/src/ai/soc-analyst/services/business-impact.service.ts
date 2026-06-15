import { Injectable, Logger } from '@nestjs/common';
import { Vulnerability } from '../../../types';

@Injectable()
export class BusinessImpactService {
  private readonly logger = new Logger(BusinessImpactService.name);

  determineImpact(vuln: Vulnerability): string[] {
    this.logger.debug(`Determining business impact for ${vuln.title}`);
    const impacts: string[] = [];
    
    if (vuln.title.toLowerCase().includes('sql') || vuln.title.toLowerCase().includes('injection')) {
      impacts.push('Potential Customer Data Exposure');
      impacts.push('Database Compromise');
    }

    if (vuln.title.toLowerCase().includes('xss') || vuln.title.toLowerCase().includes('cors')) {
      impacts.push('Session Hijacking');
      impacts.push('Client-side Code Execution');
    }

    if (impacts.length === 0) {
      impacts.push('Minor Operational Disruption');
    }

    return impacts;
  }
}
