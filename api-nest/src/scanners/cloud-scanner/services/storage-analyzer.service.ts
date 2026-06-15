import { Injectable, Logger } from '@nestjs/common';
import { CloudFinding } from '../dtos/cloud-finding.dto';

@Injectable()
export class StorageAnalyzerService {
  private readonly logger = new Logger(StorageAnalyzerService.name);

  analyze(storageConfig: any): CloudFinding[] {
    this.logger.debug('Analyzing Storage Buckets and Blobs');
    const findings: CloudFinding[] = [];

    if (JSON.stringify(storageConfig).includes('"PublicAccessBlockConfiguration":{"BlockPublicAcls":false')) {
      findings.push({
        severity: 'CRITICAL',
        platform: 'AWS',
        serviceName: 'S3',
        assetId: 's3-customer-data-bucket',
        issueType: 'Public Storage Buckets',
        description: 'S3 Bucket does not have Block Public Access enabled, risking data exposure.',
        remediation: 'Enable Block Public Access for the S3 bucket.',
      });
    }

    return findings;
  }
}
