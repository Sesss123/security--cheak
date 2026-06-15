import { Injectable, Logger } from '@nestjs/common';
import { ContainerFinding } from '../dtos/container-finding.dto';

@Injectable()
export class SecretDetectionService {
  private readonly logger = new Logger(SecretDetectionService.name);

  scanManifest(content: string): ContainerFinding[] {
    this.logger.debug('Scanning manifests for secrets');
    const findings: ContainerFinding[] = [];
    
    // Simple regex check for hardcoded secrets
    if (content.match(/password\s*[:=]\s*["'][^"']+["']/i) || content.match(/secret\s*[:=]\s*["'][^"']+["']/i)) {
      findings.push({
        severity: 'CRITICAL',
        component: 'Manifest/Dockerfile',
        issueType: 'Exposed Secrets',
        description: 'Potential hardcoded secrets detected in configuration files.',
        remediation: 'Use secure secret management solutions like HashiCorp Vault or Kubernetes Secrets.',
      });
    }

    return findings;
  }
}
