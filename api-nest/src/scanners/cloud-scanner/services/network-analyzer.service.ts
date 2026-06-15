import { Injectable, Logger } from '@nestjs/common';
import { CloudFinding } from '../dtos/cloud-finding.dto';

@Injectable()
export class NetworkAnalyzerService {
  private readonly logger = new Logger(NetworkAnalyzerService.name);

  analyze(networkConfig: any): CloudFinding[] {
    this.logger.debug('Analyzing Network Configurations (Security Groups/Firewalls)');
    const findings: CloudFinding[] = [];

    // Mock check for open port 22 or 3389
    if (JSON.stringify(networkConfig).includes('0.0.0.0/0')) {
      findings.push({
        severity: 'HIGH',
        platform: 'AWS',
        serviceName: 'EC2 Security Groups',
        assetId: 'sg-0123456789',
        issueType: 'Open Security Groups',
        description: 'A Security Group allows ingress traffic from any IP (0.0.0.0/0) to sensitive ports.',
        remediation: 'Restrict inbound traffic to known, trusted IP addresses.',
      });
    }

    return findings;
  }
}
