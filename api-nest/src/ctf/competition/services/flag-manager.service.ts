import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class FlagManagerService {
  private readonly logger = new Logger(FlagManagerService.name);

  submitFlag(teamId: string, challengeId: string, flag: string): boolean {
    this.logger.debug(`Validating flag submission for team ${teamId}`);
    // Mock logic
    return flag.startsWith('flag{');
  }
}
