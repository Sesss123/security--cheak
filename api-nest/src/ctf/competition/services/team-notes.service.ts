import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class TeamNotesService {
  private readonly logger = new Logger(TeamNotesService.name);

  saveNote(teamId: string, note: string): void {
    this.logger.debug(`Saving note for team ${teamId}`);
  }
}
