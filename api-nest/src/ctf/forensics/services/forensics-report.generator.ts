import { Injectable, Logger } from '@nestjs/common';
import { ForensicsReport } from '../dtos/forensics-report.dto';
import { MetadataExtractionService } from './metadata-extraction.service';
import { IocExtractionService } from './ioc-extraction.service';
import { TimelineGeneratorService } from './timeline-generator.service';
import { FileAnalysisService } from './file-analysis.service';
import { CorrelationEngine } from '../engines/correlation.engine';

@Injectable()
export class ForensicsReportGenerator {
  private readonly logger = new Logger(ForensicsReportGenerator.name);

  constructor(
    private readonly metadataSvc: MetadataExtractionService,
    private readonly iocSvc: IocExtractionService,
    private readonly timelineSvc: TimelineGeneratorService,
    private readonly fileAnalysis: FileAnalysisService,
    private readonly correlation: CorrelationEngine,
  ) {}

  generateReport(fileName: string, buffer: Buffer, rawText: string): ForensicsReport {
    this.logger.debug(`Generating forensics report for ${fileName}`);
    const metadata = this.metadataSvc.extract(buffer);
    const iocs = this.iocSvc.extract(rawText);
    const timeline = this.timelineSvc.generate(rawText.split('\n'));
    const artifacts = this.fileAnalysis.analyze(buffer);
    const evidenceSummary = this.correlation.correlate(iocs, timeline);

    return {
      fileName,
      metadata,
      iocs,
      timeline,
      artifacts,
      evidenceSummary,
    };
  }
}
