import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class ChallengeClassifierService {
  private readonly logger = new Logger(ChallengeClassifierService.name);

  classify(description: string): { category: string; confidence: number } {
    this.logger.debug('Classifying CTF challenge');
    const descLower = description.toLowerCase();
    if (descLower.includes('rsa') || descLower.includes('cipher')) {
      return { category: 'Crypto', confidence: 0.9 };
    }
    if (descLower.includes('xss') || descLower.includes('sql')) {
      return { category: 'Web', confidence: 0.9 };
    }
    if (descLower.includes('pcap') || descLower.includes('wireshark')) {
      return { category: 'Forensics', confidence: 0.9 };
    }
    return { category: 'Misc', confidence: 0.5 };
  }
}
