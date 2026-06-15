import { Injectable, Logger } from '@nestjs/common';
import { ReAnalysisResult } from '../dtos/re-analysis.dto';
import { BinaryParserService } from './binary-parser.service';
import { StringsAnalysisService } from './strings-analysis.service';
import { EntropyAnalyzerService } from './entropy-analyzer.service';
import { ImportAnalysisService } from './import-analysis.service';

@Injectable()
export class AiBinarySummaryService {
  private readonly logger = new Logger(AiBinarySummaryService.name);

  constructor(
    private readonly parser: BinaryParserService,
    private readonly strings: StringsAnalysisService,
    private readonly entropy: EntropyAnalyzerService,
    private readonly imports: ImportAnalysisService,
  ) {}

  generateSummary(fileName: string, buffer: Buffer): ReAnalysisResult {
    this.logger.debug(`Generating binary summary for ${fileName}`);
    const parsed = this.parser.parse(buffer);
    const stringsData = this.strings.extractStrings(buffer);
    const entropyData = this.entropy.analyze(buffer);
    const importsData = this.imports.analyzeImports(buffer);

    return {
      fileName,
      architecture: parsed.architecture,
      interestingStrings: stringsData,
      suspiciousImports: importsData,
      highEntropySections: entropyData,
      potentialFlagLocations: stringsData.filter(s => s.includes('flag{')),
      summary: `Analyzed ${parsed.fileFormat} binary. Found suspicious imports indicating potential packing or shellcode execution.`,
    };
  }
}
