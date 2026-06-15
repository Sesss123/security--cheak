import { Injectable, Logger } from '@nestjs/common';
import { ReconFinding } from '../dtos/recon-report.dto';

@Injectable()
export class TechnologyFingerprintService {
  private readonly logger = new Logger(TechnologyFingerprintService.name);

  async fingerprint(url: string, html: string, headers: any): Promise<ReconFinding[]> {
    this.logger.debug(`Fingerprinting technologies for ${url}`);
    const findings: ReconFinding[] = [];
    if (headers['x-powered-by']?.includes('Express')) {
      findings.push({ type: 'TECHNOLOGY', value: 'Express.js', confidence: 0.95 });
    }
    if (html.includes('React')) {
      findings.push({ type: 'TECHNOLOGY', value: 'React', confidence: 0.8 });
    }
    return findings;
  }
}
