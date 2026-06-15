import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class HashAnalyzerService {
  private readonly logger = new Logger(HashAnalyzerService.name);

  analyze(hash: string): string {
    this.logger.debug('Analyzing hash');
    if (hash.length === 32) return 'MD5';
    if (hash.length === 40) return 'SHA1';
    if (hash.length === 64) return 'SHA256';
    if (hash.length === 128) return 'SHA512';
    return 'Unknown Hash Format';
  }
}
