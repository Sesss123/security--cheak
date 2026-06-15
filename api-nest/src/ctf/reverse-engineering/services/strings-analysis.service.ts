import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class StringsAnalysisService {
  private readonly logger = new Logger(StringsAnalysisService.name);

  extractStrings(buffer: Buffer): string[] {
    this.logger.debug('Extracting readable strings');
    // Mock string extraction
    return ['flag{', 'password', 'admin', 'http://'];
  }
}
