import { Injectable, Logger } from '@nestjs/common';
import { CveDetail } from '../dtos/enrichment.dto';

@Injectable()
export class CveService {
  private readonly logger = new Logger(CveService.name);

  async getCveDetails(cveId: string): Promise<CveDetail | null> {
    this.logger.debug(`Fetching details for ${cveId} from NVD...`);
    // In production, call NVD API: fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`)
    
    // Mock response for now
    if (cveId.startsWith('CVE-')) {
      return {
        id: cveId,
        cvssV3Score: Math.random() * 5 + 5, // Random 5.0 to 10.0
        description: `Vulnerability described in ${cveId}`,
        publishedDate: new Date().toISOString(),
      };
    }
    return null;
  }
}
