import { Injectable, Logger } from '@nestjs/common';
import { Vulnerability } from '../../types';
import { AttackGraph, AttackNode, AttackEdge } from '../dtos/attack-chain.dto';

@Injectable()
export class AttackGraphService {
  private readonly logger = new Logger(AttackGraphService.name);

  buildGraph(vulns: Vulnerability[]): AttackGraph {
    this.logger.debug(`Building attack graph for ${vulns.length} findings`);
    
    const nodes: AttackNode[] = vulns.map(v => ({
      id: v.id,
      vulnId: v.id,
      title: v.title,
      severity: v.severity,
    }));

    const edges: AttackEdge[] = [];

    // Basic heuristic building
    for (const source of nodes) {
      for (const target of nodes) {
        if (source.id === target.id) continue;
        
        // Example logic: Cross-Site Scripting (XSS) enables Session Hijacking or Privilege Escalation
        if (source.title.toLowerCase().includes('xss') && target.title.toLowerCase().includes('privilege')) {
          edges.push({ from: source.id, to: target.id, relationship: 'Enables' });
        }
        
        // Example logic: Missing CSP enables XSS
        if (source.title.toLowerCase().includes('csp') && target.title.toLowerCase().includes('xss')) {
          edges.push({ from: source.id, to: target.id, relationship: 'Facilitates' });
        }
      }
    }

    return { nodes, edges };
  }
}
