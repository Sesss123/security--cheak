import { Injectable, Logger } from '@nestjs/common';
import { ContainerFinding } from '../dtos/container-finding.dto';

@Injectable()
export class KubernetesAnalyzer {
  private readonly logger = new Logger(KubernetesAnalyzer.name);

  analyzeManifest(manifestContent: string): ContainerFinding[] {
    this.logger.debug('Analyzing Kubernetes YAML manifest');
    const findings: ContainerFinding[] = [];
    
    if (manifestContent.includes('privileged: true')) {
      findings.push({
        severity: 'CRITICAL',
        component: 'K8s Manifest',
        issueType: 'Privileged Containers',
        description: 'Pod requests privileged access, allowing it to bypass most container isolation mechanisms.',
        remediation: 'Remove the `privileged: true` security context unless absolutely necessary.',
      });
    }

    if (manifestContent.includes('hostNetwork: true')) {
      findings.push({
        severity: 'HIGH',
        component: 'K8s Manifest',
        issueType: 'Dangerous Capabilities',
        description: 'Pod shares the host network namespace.',
        remediation: 'Set hostNetwork to false to ensure proper network isolation.',
      });
    }

    return findings;
  }
}
