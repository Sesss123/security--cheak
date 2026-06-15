import { Injectable, Logger } from '@nestjs/common';
import { AttackGraph, AttackNode } from '../dtos/attack-chain.dto';
import { CorrelationEngine } from '../engines/correlation.engine';

@Injectable()
export class RiskPathAnalyzer {
  private readonly logger = new Logger(RiskPathAnalyzer.name);

  constructor(private readonly correlationEngine: CorrelationEngine) {}

  analyze(graph: AttackGraph): AttackNode[][] {
    this.logger.debug('Analyzing risk paths in graph');
    
    // Identify entry points (e.g. low severity / external facing)
    const entryPoints = graph.nodes.filter(n => ['LOW', 'MEDIUM', 'INFO'].includes(n.severity));
    
    // Identify critical targets (e.g. RCE, SQLi, Admin Access)
    const criticalTargets = graph.nodes.filter(n => ['HIGH', 'CRITICAL'].includes(n.severity));

    const riskPaths: AttackNode[][] = [];

    for (const entry of entryPoints) {
      for (const target of criticalTargets) {
        const paths = this.correlationEngine.findPaths(graph, entry.id, target.id);
        riskPaths.push(...paths);
      }
    }

    return riskPaths;
  }
}
