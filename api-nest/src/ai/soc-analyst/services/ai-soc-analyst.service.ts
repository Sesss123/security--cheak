import { Injectable, Logger } from '@nestjs/common';
import { Vulnerability } from '../../../types';
import { SocAnalystReport } from '../dtos/soc-analyst-report.dto';
import { RiskAssessmentService } from './risk-assessment.service';
import { AttackProbabilityService } from './attack-probability.service';
import { BusinessImpactService } from './business-impact.service';
import { AssetCriticalityService } from './asset-criticality.service';
import { MitigationPlannerService } from './mitigation-planner.service';
import { ExecutiveSummaryGenerator } from './executive-summary.generator';

@Injectable()
export class AiSocAnalystService {
  private readonly logger = new Logger(AiSocAnalystService.name);

  constructor(
    private readonly riskAssessment: RiskAssessmentService,
    private readonly attackProbability: AttackProbabilityService,
    private readonly businessImpact: BusinessImpactService,
    private readonly assetCriticality: AssetCriticalityService,
    private readonly mitigationPlanner: MitigationPlannerService,
    private readonly summaryGenerator: ExecutiveSummaryGenerator,
  ) {}

  analyze(vuln: Vulnerability): SocAnalystReport {
    this.logger.debug(`Performing SOC Analyst Analysis for ${vuln.id}`);

    const riskLevel = this.riskAssessment.assessRisk(vuln);
    const affectedAssets = this.assetCriticality.getAffectedAssets(vuln);
    const attackProbability = this.attackProbability.calculateProbability(vuln);
    const businessImpact = this.businessImpact.determineImpact(vuln);
    const recommendedFix = this.mitigationPlanner.planMitigation(vuln);
    const executiveSummary = this.summaryGenerator.generateSummary(vuln, riskLevel, businessImpact);

    return {
      riskLevel,
      affectedAssets,
      attackProbability,
      businessImpact,
      threatIntelligence: {
        relatedCwe: vuln.cwe_id ? `CWE-${vuln.cwe_id}` : undefined,
        relatedCve: vuln.cve_id,
        exploitAvailable: vuln.exploit_available,
      },
      recommendedFix,
      executiveSummary,
    };
  }
}
