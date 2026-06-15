import { Injectable, Logger } from '@nestjs/common';
import { WebAnalysisResult } from '../dtos/web-analysis.dto';

@Injectable()
export class CookieAnalyzerService {
  private readonly logger = new Logger(CookieAnalyzerService.name);

  analyze(cookieString: string): WebAnalysisResult {
    this.logger.debug('Analyzing cookie string');
    const observations: string[] = [];
    if (!cookieString.toLowerCase().includes('httponly')) {
      observations.push('Cookie is missing HttpOnly flag.');
    }
    if (!cookieString.toLowerCase().includes('secure')) {
      observations.push('Cookie is missing Secure flag.');
    }
    return {
      inputType: 'COOKIE',
      decodedData: cookieString,
      securityObservations: observations,
    };
  }
}
