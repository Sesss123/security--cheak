import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { Vulnerability } from '../../types';
import { AttackGraphService } from './attack-graph.service';
import { RiskPathAnalyzer } from './risk-path.analyzer';
import { MitreMapper } from './mitre.mapper';
import { AttackChain, AttackNode } from '../dtos/attack-chain.dto';

@Injectable()
export class AttackChainGenerator {
  private readonly logger = new Logger(AttackChainGenerator.name);

  constructor(
    private readonly attackGraphService: AttackGraphService,
    private readonly riskPathAnalyzer: RiskPathAnalyzer,
    private readonly mitreMapper: MitreMapper,
  ) {}

  generateChains(vulns: Vulnerability[]): AttackChain[] {
    this.logger.log(`Generating attack chains for ${vulns.length} vulnerabilities`);
    
    const graph = this.attackGraphService.buildGraph(vulns);
    const criticalPaths = this.riskPathAnalyzer.analyze(graph);

    return criticalPaths.map(path => {
      const tactics = this.mitreMapper.mapPathToTactics(path);
      
      let impact = "Minor operational disruption.";
      if (tactics.some(t => t.includes('Privilege Escalation') || t.includes('Credential Access'))) {
        impact = "Potential full system compromise and data exfiltration.";
      }

      return {
        id: randomUUID(),
        steps: path,
        mitreTactics: tactics,
        businessImpact: impact,
        riskScore: this.calculateRiskScore(path),
      };
    });
  }

  private calculateRiskScore(path: AttackNode[]): number {
    let score = 0;
    for (const node of path) {
      if (node.severity === 'CRITICAL') score += 10;
      if (node.severity === 'HIGH') score += 7;
      if (node.severity === 'MEDIUM') score += 4;
      if (node.severity === 'LOW') score += 1;
    }
    return Math.min(score, 10);
  }
}
