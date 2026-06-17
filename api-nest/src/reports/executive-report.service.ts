import { Injectable, Logger } from '@nestjs/common';
import { AiService } from '../services/ai.service';

@Injectable()
export class ExecutiveReportService {
  private readonly logger = new Logger(ExecutiveReportService.name);

  constructor(
    private readonly aiService: AiService,
  ) {}

  async generateExecutiveSummary(scanResult: any): Promise<any> {
    this.logger.log(`Generating Executive Summary for Scan ID: ${scanResult.scan_id}`);

    const prompt = `
      Convert the following technical findings into an executive summary.
      Include: Risk Level, Affected Assets, Business Impact, and Recommended Actions.
      Do not include raw JSON or overly technical exploit details.
      Data: ${JSON.stringify(scanResult)}
    `;

    // Using the AI Service to generate human-readable report
    const reportText = await this.aiService.analyzeRisk(scanResult.vulnerabilities || []);

    return {
      riskLevel: scanResult.summary?.risk_score > 7 ? 'Critical' : 'Medium',
      affectedAssets: [scanResult.target_url],
      businessImpact: reportText, // Typically the LLM output will contain this
      recommendedActions: ["Immediate Patching", "Configuration Hardening"],
    };
  }
}
