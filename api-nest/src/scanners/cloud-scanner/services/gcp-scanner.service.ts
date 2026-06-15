import { Injectable, Logger } from '@nestjs/common';
import { CloudFinding } from '../dtos/cloud-finding.dto';

@Injectable()
export class GcpScannerService {
  private readonly logger = new Logger(GcpScannerService.name);

  scan(configData: any): CloudFinding[] {
    this.logger.debug('Scanning GCP Configuration');
    return [];
  }
}
