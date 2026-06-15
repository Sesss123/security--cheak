import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class EncodingDetectorService {
  private readonly logger = new Logger(EncodingDetectorService.name);

  detect(input: string): string {
    this.logger.debug('Detecting encoding');
    if (/^[A-Za-z0-9+/=]+$/.test(input) && input.length % 4 === 0) return 'Base64';
    if (/^[0-9A-Fa-f]+$/.test(input)) return 'Hex';
    return 'Unknown / Plaintext';
  }
}
