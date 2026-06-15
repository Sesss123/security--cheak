import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class EvidenceBoardService {
  private readonly logger = new Logger(EvidenceBoardService.name);

  addEvidence(teamId: string, evidenceUrl: string): void {
    this.logger.debug(`Adding evidence to board for team ${teamId}`);
  }
}
