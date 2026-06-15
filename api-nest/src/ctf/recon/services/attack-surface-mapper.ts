import { Injectable, Logger } from '@nestjs/common';
import { ReconFinding } from '../dtos/recon-report.dto';

@Injectable()
export class AttackSurfaceMapper {
  private readonly logger = new Logger(AttackSurfaceMapper.name);

  mapSurface(findings: ReconFinding[]): any {
    this.logger.debug('Mapping attack surface from recon findings');
    return {
      totalVectors: findings.length,
      highConfidenceVectors: findings.filter(f => f.confidence > 0.8).length,
    };
  }
}
