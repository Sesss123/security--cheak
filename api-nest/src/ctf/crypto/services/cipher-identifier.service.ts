import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class CipherIdentifierService {
  private readonly logger = new Logger(CipherIdentifierService.name);

  identify(input: string): string {
    this.logger.debug('Identifying potential cipher');
    // Basic heuristic: check if it looks like ROT13 or Caesar
    if (/^[A-Za-z]+$/.test(input)) return 'ROT13 / Caesar / Vigenere';
    if (input.includes('-----BEGIN PUBLIC KEY-----')) return 'RSA';
    return 'Unknown Cipher';
  }
}
