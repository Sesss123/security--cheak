import { Injectable, Logger } from '@nestjs/common';
import { WebAnalysisResult } from '../dtos/web-analysis.dto';

@Injectable()
export class Base64AnalysisService {
  private readonly logger = new Logger(Base64AnalysisService.name);

  analyze(input: string): WebAnalysisResult {
    this.logger.debug('Analyzing Base64 string');
    try {
      const decoded = Buffer.from(input, 'base64').toString();
      return {
        inputType: 'BASE64',
        decodedData: decoded,
        securityObservations: [],
      };
    } catch (e) {
      return { inputType: 'BASE64', decodedData: 'Invalid Base64', securityObservations: [] };
    }
  }
}
