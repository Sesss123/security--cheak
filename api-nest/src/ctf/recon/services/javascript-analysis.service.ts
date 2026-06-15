import { Injectable, Logger } from '@nestjs/common';
import { ReconFinding } from '../dtos/recon-report.dto';

@Injectable()
export class JavascriptAnalysisService {
  private readonly logger = new Logger(JavascriptAnalysisService.name);

  async analyze(jsContent: string): Promise<ReconFinding[]> {
    this.logger.debug('Analyzing JS files for secrets or endpoints');
    const findings: ReconFinding[] = [];
    if (jsContent.includes('api_key')) {
      findings.push({ type: 'JS_FILE', value: 'Potential hardcoded API key in JS', confidence: 0.8 });
    }
    return findings;
  }
}
