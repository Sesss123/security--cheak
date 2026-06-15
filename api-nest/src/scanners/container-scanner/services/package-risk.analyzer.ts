import { Injectable, Logger } from '@nestjs/common';
import { ContainerFinding } from '../dtos/container-finding.dto';

@Injectable()
export class PackageRiskAnalyzer {
  private readonly logger = new Logger(PackageRiskAnalyzer.name);

  analyzeBaseImage(baseImage: string): ContainerFinding[] {
    this.logger.debug(`Analyzing base image risk for ${baseImage}`);
    const findings: ContainerFinding[] = [];
    
    if (baseImage.includes('ubuntu') || baseImage.includes('debian')) {
      findings.push({
        severity: 'LOW',
        component: 'Base Image',
        issueType: 'Package Risk',
        description: 'Using full OS distributions increases the attack surface.',
        remediation: 'Consider using minimal base images like Alpine or distroless images.',
      });
    }

    return findings;
  }
}
