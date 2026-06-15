import { Injectable, Logger } from '@nestjs/common';
import { WebAnalysisResult } from '../dtos/web-analysis.dto';

@Injectable()
export class HashIdentifierService {
  private readonly logger = new Logger(HashIdentifierService.name);

  identify(hash: string): WebAnalysisResult {
    this.logger.debug('Identifying hash type');
    let type = 'Unknown';
    if (hash.length === 32) type = 'MD5 / NTLM';
    if (hash.length === 40) type = 'SHA-1';
    if (hash.length === 64) type = 'SHA-256';

    return {
      inputType: 'HASH',
      decodedData: `Possible Hash Type: ${type}`,
      securityObservations: [],
    };
  }
}
