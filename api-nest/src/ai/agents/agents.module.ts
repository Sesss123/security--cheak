import { Module } from '@nestjs/common';
import { ReconAgent } from './recon.agent';
import { ThreatAgent } from './threat.agent';
import { ForensicsAgent } from './forensics.agent';
import { AttackChainAgent } from './attack-chain.agent';
import { SocAnalystAgent } from './soc-analyst.agent';
import { DirectorService } from './director.service';
import { DatabaseModule } from '../../db/database.module';
import { AgentsController } from './agents.controller';
@Module({
  imports: [DatabaseModule],
  controllers: [AgentsController],
  providers: [
    ReconAgent,
    ThreatAgent,
    ForensicsAgent,
    AttackChainAgent,
    SocAnalystAgent,
    DirectorService
  ],
  exports: [DirectorService]
})
export class AgentsModule {}
