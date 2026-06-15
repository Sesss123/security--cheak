import { Module } from '@nestjs/common';
import { ChallengeTrackerService } from './services/challenge-tracker.service';
import { TeamNotesService } from './services/team-notes.service';
import { EvidenceBoardService } from './services/evidence-board.service';
import { TimelineService } from './services/timeline.service';
import { FlagManagerService } from './services/flag-manager.service';
import { TeamCollaborationGateway } from './gateways/team-collaboration.gateway';

@Module({
  providers: [
    ChallengeTrackerService,
    TeamNotesService,
    EvidenceBoardService,
    TimelineService,
    FlagManagerService,
    TeamCollaborationGateway,
  ],
  exports: [ChallengeTrackerService, FlagManagerService],
})
export class CompetitionModule {}
