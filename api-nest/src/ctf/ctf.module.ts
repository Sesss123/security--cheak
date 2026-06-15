import { Module } from '@nestjs/common';
import { CtfController } from './ctf.controller';
import { TeamGateway } from './team.gateway';
import { ReconModule } from './recon/recon.module';
import { ChallengeAnalyzerModule } from './challenge-analyzer/challenge-analyzer.module';
import { WebHelperModule } from './web-helper/web-helper.module';
import { ForensicsModule } from './forensics/forensics.module';
import { CryptoModule } from './crypto/crypto.module';
import { ReverseEngineeringModule } from './reverse-engineering/re.module';
import { KnowledgeBaseModule } from './knowledge-base/knowledge-base.module';
import { CompetitionModule } from './competition/competition.module';

@Module({
  imports: [
    ReconModule,
    ChallengeAnalyzerModule,
    WebHelperModule,
    ForensicsModule,
    CryptoModule,
    ReverseEngineeringModule,
    KnowledgeBaseModule,
    CompetitionModule,
  ],
  controllers: [CtfController],
  providers: [TeamGateway],
  exports: [TeamGateway],
})
export class CtfModule {}
