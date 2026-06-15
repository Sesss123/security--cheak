import { Injectable, Logger } from '@nestjs/common';
import { CloudFinding } from '../dtos/cloud-finding.dto';

@Injectable()
export class AwsScannerService {
  private readonly logger = new Logger(AwsScannerService.name);

  scan(configData: any): CloudFinding[] {
    this.logger.debug('Scanning AWS Configuration');
    // Mocking AWS configuration scan
    return [];
  }
}
