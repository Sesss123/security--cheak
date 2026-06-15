import { Module } from '@nestjs/common';
import { RiskAssessmentService } from './services/risk-assessment.service';
import { AttackProbabilityService } from './services/attack-probability.service';
import { BusinessImpactService } from './services/business-impact.service';
import { AssetCriticalityService } from './services/asset-criticality.service';
import { MitigationPlannerService } from './services/mitigation-planner.service';
import { ExecutiveSummaryGenerator } from './services/executive-summary.generator';
import { AiSocAnalystService } from './services/ai-soc-analyst.service';

@Module({
  providers: [
    RiskAssessmentService,
    AttackProbabilityService,
    BusinessImpactService,
    AssetCriticalityService,
    MitigationPlannerService,
    ExecutiveSummaryGenerator,
    AiSocAnalystService,
  ],
  exports: [
    AiSocAnalystService,
  ],
})
export class SocAnalystModule {}
