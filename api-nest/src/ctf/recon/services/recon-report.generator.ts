import { Injectable, Logger } from '@nestjs/common';
import { ReconFinding, ReconReport } from '../dtos/recon-report.dto';
import { AttackSurfaceMapper } from './attack-surface-mapper';

@Injectable()
export class ReconReportGenerator {
  private readonly logger = new Logger(ReconReportGenerator.name);

  constructor(private readonly surfaceMapper: AttackSurfaceMapper) {}

  generate(target: string, findings: ReconFinding[]): ReconReport {
    this.logger.debug(`Generating recon report for ${target}`);
    return {
      target,
      technologies: findings.filter(f => f.type === 'TECHNOLOGY').map(f => f.value),
      subdomains: findings.filter(f => f.type === 'SUBDOMAIN').map(f => f.value),
      interestingFiles: findings.filter(f => f.type === 'JS_FILE').map(f => f.value),
      exposedServices: findings.filter(f => f.type === 'ENDPOINT').map(f => f.value),
      attackSurfaceMap: this.surfaceMapper.mapSurface(findings),
      findings,
    };
  }
}
