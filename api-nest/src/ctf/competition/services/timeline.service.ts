import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class TimelineService {
  private readonly logger = new Logger(TimelineService.name);

  logEvent(teamId: string, event: string): void {
    this.logger.debug(`Logging competition event for team ${teamId}: ${event}`);
  }
}
