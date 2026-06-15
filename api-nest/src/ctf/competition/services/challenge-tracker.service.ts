import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class ChallengeTrackerService {
  private readonly logger = new Logger(ChallengeTrackerService.name);

  trackProgress(teamId: string, challengeId: string, status: string): void {
    this.logger.debug(`Tracking challenge ${challengeId} for team ${teamId} as ${status}`);
  }
}
