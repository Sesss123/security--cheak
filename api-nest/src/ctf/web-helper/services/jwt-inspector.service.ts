import { Injectable, Logger } from '@nestjs/common';
import { WebAnalysisResult } from '../dtos/web-analysis.dto';

@Injectable()
export class JwtInspectorService {
  private readonly logger = new Logger(JwtInspectorService.name);

  inspect(jwt: string): WebAnalysisResult {
    this.logger.debug('Inspecting JWT');
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return { inputType: 'JWT', decodedData: 'Invalid JWT format', securityObservations: ['Format incorrect'] };
    }
    
    try {
      const header = Buffer.from(parts[0], 'base64').toString();
      const payload = Buffer.from(parts[1], 'base64').toString();
      const observations: string[] = [];
      
      if (header.includes('"alg":"none"')) {
        observations.push('Warning: Algorithm set to "none".');
      }

      return {
        inputType: 'JWT',
        decodedData: `Header: ${header}\nPayload: ${payload}`,
        securityObservations: observations,
      };
    } catch (e) {
      return { inputType: 'JWT', decodedData: 'Failed to decode', securityObservations: ['Decode error'] };
    }
  }
}
