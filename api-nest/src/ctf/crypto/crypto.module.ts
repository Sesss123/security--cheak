import { Module } from '@nestjs/common';
import { EncodingDetectorService } from './services/encoding-detector.service';
import { CipherIdentifierService } from './services/cipher-identifier.service';
import { HashAnalyzerService } from './services/hash-analyzer.service';
import { TransformationService } from './services/transformation.service';
import { CryptoHintService } from './services/crypto-hint.service';

@Module({
  providers: [
    EncodingDetectorService,
    CipherIdentifierService,
    HashAnalyzerService,
    TransformationService,
    CryptoHintService,
  ],
  exports: [CryptoHintService, TransformationService],
})
export class CryptoModule {}
