import { Module } from '@nestjs/common';
import { MetadataExtractionService } from './services/metadata-extraction.service';
import { IocExtractionService } from './services/ioc-extraction.service';
import { TimelineGeneratorService } from './services/timeline-generator.service';
import { FileAnalysisService } from './services/file-analysis.service';
import { CorrelationEngine } from './engines/correlation.engine';
import { ForensicsReportGenerator } from './services/forensics-report.generator';

@Module({
  providers: [
    MetadataExtractionService,
    IocExtractionService,
    TimelineGeneratorService,
    FileAnalysisService,
    CorrelationEngine,
    ForensicsReportGenerator,
  ],
  exports: [ForensicsReportGenerator, FileAnalysisService],
})
export class ForensicsModule {}
