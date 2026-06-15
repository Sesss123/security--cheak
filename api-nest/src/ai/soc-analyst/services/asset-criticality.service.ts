import { Injectable, Logger } from '@nestjs/common';
import { Vulnerability } from '../../../types';

@Injectable()
export class AssetCriticalityService {
  private readonly logger = new Logger(AssetCriticalityService.name);

  getAffectedAssets(vuln: Vulnerability): string[] {
    this.logger.debug(`Extracting affected assets for ${vuln.title}`);
    const assets = [vuln.affected_url];
    if (vuln.affected_parameter) {
      assets.push(`Parameter: ${vuln.affected_parameter}`);
    }
    return assets;
  }
}
