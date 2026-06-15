import { Module } from '@nestjs/common';
import { AttackGraphService } from './services/attack-graph.service';
import { CorrelationEngine } from './engines/correlation.engine';
import { RiskPathAnalyzer } from './services/risk-path.analyzer';
import { MitreMapper } from './services/mitre.mapper';
import { AttackChainGenerator } from './services/attack-chain.generator';

@Module({
  providers: [
    AttackGraphService,
    CorrelationEngine,
    RiskPathAnalyzer,
    MitreMapper,
    AttackChainGenerator,
  ],
  exports: [
    AttackChainGenerator,
  ],
})
export class AttackChainModule {}
