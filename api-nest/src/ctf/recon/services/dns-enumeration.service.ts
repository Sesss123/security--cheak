import { Injectable, Logger } from '@nestjs/common';
import { ReconFinding } from '../dtos/recon-report.dto';

@Injectable()
export class DnsEnumerationService {
  private readonly logger = new Logger(DnsEnumerationService.name);

  async enumerate(domain: string): Promise<ReconFinding[]> {
    this.logger.debug(`Enumerating DNS for ${domain}`);
    return [
      { type: 'DNS', value: `TXT: v=spf1 include:_spf.example.com ~all`, confidence: 1.0 },
    ];
  }
}
