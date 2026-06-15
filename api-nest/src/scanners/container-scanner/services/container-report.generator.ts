import { Injectable, Logger } from '@nestjs/common';
import { ContainerFinding, ContainerReport } from '../dtos/container-finding.dto';

@Injectable()
export class ContainerReportGenerator {
  private readonly logger = new Logger(ContainerReportGenerator.name);

  generateReport(target: string, findings: ContainerFinding[]): ContainerReport {
    this.logger.debug(`Generating Container Report for ${target}`);
    
    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const misconfigurationsCount = findings.filter(f => f.component === 'K8s Manifest' || f.component === 'Dockerfile').length;

    return {
      target,
      findings,
      criticalCount,
      misconfigurationsCount,
    };
  }
}
