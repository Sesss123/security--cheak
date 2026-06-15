import { Injectable, Logger } from '@nestjs/common';
import { WebAnalysisResult } from '../dtos/web-analysis.dto';

@Injectable()
export class UrlUtilityService {
  private readonly logger = new Logger(UrlUtilityService.name);

  analyze(url: string): WebAnalysisResult {
    this.logger.debug('Analyzing URL encoded string');
    return {
      inputType: 'URL',
      decodedData: decodeURIComponent(url),
      securityObservations: [],
    };
  }
}
