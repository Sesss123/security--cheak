import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class TimelineGeneratorService {
  private readonly logger = new Logger(TimelineGeneratorService.name);

  generate(logEntries: string[]): any[] {
    this.logger.debug('Generating timeline from logs');
    // Mock parsing timestamps
    return logEntries.map((log, index) => ({ id: index, event: log, time: new Date().toISOString() }));
  }
}
