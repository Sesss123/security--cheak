import { Injectable, Logger } from '@nestjs/common';
import { WebAnalysisResult } from '../dtos/web-analysis.dto';

@Injectable()
export class HttpInspectorService {
  private readonly logger = new Logger(HttpInspectorService.name);

  inspect(requestText: string): WebAnalysisResult {
    this.logger.debug('Inspecting HTTP request');
    const observations: string[] = [];
    if (requestText.includes('Transfer-Encoding: chunked')) {
      observations.push('Chunked encoding detected. Check for HTTP Request Smuggling (TE.CL / CL.TE).');
    }
    return {
      inputType: 'HTTP',
      decodedData: requestText,
      securityObservations: observations,
    };
  }
}
