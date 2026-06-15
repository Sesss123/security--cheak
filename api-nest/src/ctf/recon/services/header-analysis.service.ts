import { Injectable, Logger } from '@nestjs/common';
import { ReconFinding } from '../dtos/recon-report.dto';

@Injectable()
export class HeaderAnalysisService {
  private readonly logger = new Logger(HeaderAnalysisService.name);

  async analyze(headers: any): Promise<ReconFinding[]> {
    this.logger.debug('Analyzing HTTP Headers for Recon');
    const findings: ReconFinding[] = [];
    if (headers['server']) {
      findings.push({ type: 'HEADER', value: `Server: ${headers['server']}`, confidence: 1.0 });
    }
    return findings;
  }
}
