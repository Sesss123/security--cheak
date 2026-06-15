import { Injectable } from '@nestjs/common';
import { AttackNode } from '../dtos/attack-chain.dto';

@Injectable()
export class MitreMapper {
  
  mapNodeToTactic(node: AttackNode): string[] {
    const title = node.title.toLowerCase();
    const tactics: string[] = [];

    if (title.includes('sql') || title.includes('injection')) {
      tactics.push('TA0001: Initial Access');
      tactics.push('TA0006: Credential Access');
    }
    
    if (title.includes('xss') || title.includes('cross-site')) {
      tactics.push('TA0001: Initial Access');
    }

    if (title.includes('privilege') || title.includes('auth')) {
      tactics.push('TA0004: Privilege Escalation');
    }

    if (tactics.length === 0) {
      tactics.push('TA0040: Impact');
    }

    return tactics;
  }

  mapPathToTactics(path: AttackNode[]): string[] {
    const tactics = new Set<string>();
    for (const node of path) {
      this.mapNodeToTactic(node).forEach(t => tactics.add(t));
    }
    return Array.from(tactics);
  }
}
