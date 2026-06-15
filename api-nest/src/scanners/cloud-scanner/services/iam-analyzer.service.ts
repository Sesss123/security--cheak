import { Injectable, Logger } from '@nestjs/common';
import { CloudFinding } from '../dtos/cloud-finding.dto';

@Injectable()
export class IamAnalyzerService {
  private readonly logger = new Logger(IamAnalyzerService.name);

  analyze(iamConfig: any): CloudFinding[] {
    this.logger.debug('Analyzing IAM configurations for excessive privileges');
    const findings: CloudFinding[] = [];

    // Mock check for wildcard permissions
    if (JSON.stringify(iamConfig).includes('"Action":"*"')) {
      findings.push({
        severity: 'CRITICAL',
        platform: 'AWS',
        serviceName: 'IAM',
        assetId: 'Role/AdminOverlyPermissive',
        issueType: 'Excessive Privileges',
        description: 'An IAM policy contains a wildcard (*) action, granting full administrative access.',
        remediation: 'Implement the principle of least privilege. Replace wildcards with specific required actions.',
        complianceViolations: ['CIS AWS Foundations Benchmark 1.22'],
      });
    }

    return findings;
  }
}
