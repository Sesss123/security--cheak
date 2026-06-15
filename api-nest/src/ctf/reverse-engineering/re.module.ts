import { Module } from '@nestjs/common';
import { BinaryParserService } from './services/binary-parser.service';
import { StringsAnalysisService } from './services/strings-analysis.service';
import { EntropyAnalyzerService } from './services/entropy-analyzer.service';
import { ImportAnalysisService } from './services/import-analysis.service';
import { AiBinarySummaryService } from './services/ai-binary-summary.service';
import { MetadataExtractorService } from './services/metadata-extractor.service';

@Module({
  providers: [
    BinaryParserService,
    StringsAnalysisService,
    EntropyAnalyzerService,
    ImportAnalysisService,
    AiBinarySummaryService,
    MetadataExtractorService,
  ],
  exports: [AiBinarySummaryService],
})
export class ReverseEngineeringModule {}
