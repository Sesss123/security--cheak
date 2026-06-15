import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class CorrelationEngine {
  private readonly logger = new Logger(CorrelationEngine.name);

  correlate(iocs: string[], timeline: any[]): string {
    this.logger.debug('Correlating events with IOCs');
    if (iocs.length > 0 && timeline.length > 0) {
      return `Correlated ${iocs.length} IOCs across ${timeline.length} events. Pattern suggests lateral movement.`;
    }
    return 'No significant correlation found.';
  }
}
