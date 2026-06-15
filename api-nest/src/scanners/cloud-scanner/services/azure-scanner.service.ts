import { Injectable, Logger } from '@nestjs/common';
import { CloudFinding } from '../dtos/cloud-finding.dto';

@Injectable()
export class AzureScannerService {
  private readonly logger = new Logger(AzureScannerService.name);

  scan(configData: any): CloudFinding[] {
    this.logger.debug('Scanning Azure Configuration');
    return [];
  }
}
