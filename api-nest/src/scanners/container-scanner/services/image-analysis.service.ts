import { Injectable, Logger } from '@nestjs/common';
import { ContainerFinding } from '../dtos/container-finding.dto';

@Injectable()
export class ImageAnalysisService {
  private readonly logger = new Logger(ImageAnalysisService.name);

  analyzeDockerfile(dockerfileContent: string): ContainerFinding[] {
    this.logger.debug('Analyzing Dockerfile for insecure patterns');
    const findings: ContainerFinding[] = [];
    
    if (dockerfileContent.includes('USER root') || !dockerfileContent.includes('USER')) {
      findings.push({
        severity: 'HIGH',
        component: 'Dockerfile',
        issueType: 'Privileged Container',
        description: 'Image runs as root by default.',
        remediation: 'Specify a non-root user via the USER instruction.',
      });
    }

    if (dockerfileContent.includes('ADD ')) {
      findings.push({
        severity: 'MEDIUM',
        component: 'Dockerfile',
        issueType: 'Insecure Image Settings',
        description: 'Usage of ADD instruction can lead to unintended remote execution or tar extraction.',
        remediation: 'Use COPY instead of ADD unless tar extraction is specifically required.',
      });
    }

    return findings;
  }
}
