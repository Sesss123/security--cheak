import { Injectable, Logger } from '@nestjs/common';
import { CryptoAnalysisResult } from '../dtos/crypto-analysis.dto';
import { EncodingDetectorService } from './encoding-detector.service';
import { CipherIdentifierService } from './cipher-identifier.service';
import { HashAnalyzerService } from './hash-analyzer.service';

@Injectable()
export class CryptoHintService {
  private readonly logger = new Logger(CryptoHintService.name);

  constructor(
    private readonly encoding: EncodingDetectorService,
    private readonly cipher: CipherIdentifierService,
    private readonly hash: HashAnalyzerService,
  ) {}

  generateHints(input: string): CryptoAnalysisResult {
    this.logger.debug('Generating crypto hints');
    const encoding = this.encoding.detect(input);
    const cipher = this.cipher.identify(input);
    
    let nextStep = 'Try decoding base64/hex first.';
    if (encoding === 'Unknown / Plaintext') {
      nextStep = 'Analyze character frequency for substitution ciphers.';
    }

    return {
      detectedEncoding: encoding,
      possibleCipher: cipher,
      suggestedNextStep: nextStep,
      confidenceScore: 0.8,
    };
  }
}
