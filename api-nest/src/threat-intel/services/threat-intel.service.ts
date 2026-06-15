import { Injectable, Logger } from '@nestjs/common';
import { CveService } from './cve.service';
import { CisaService } from './cisa.service';
import { ExploitIntelService } from './exploit-intel.service';
import { ThreatCorrelationEngine } from '../engines/threat-correlation.engine';
import { Vulnerability } from '../../types';
import { EnrichmentData } from '../dtos/enrichment.dto';

@Injectable()
export class ThreatIntelService {
  private readonly logger = new Logger(ThreatIntelService.name);

  constructor(
    private readonly cveService: CveService,
    private readonly cisaService: CisaService,
    private readonly exploitService: ExploitIntelService,
    private readonly correlationEngine: ThreatCorrelationEngine,
  ) {}

  async enrichVulnerability(vuln: Vulnerability): Promise<EnrichmentData> {
    this.logger.debug(`Enriching vulnerability: ${vuln.title}`);

    let cveDetails: any = null;
    let isCisaKev = false;

    if (vuln.cve_id) {
      cveDetails = await this.cveService.getCveDetails(vuln.cve_id);
      isCisaKev = await this.cisaService.isKnownExploitedCve(vuln.cve_id);
    }

    let cweId: number | undefined;
    if (vuln.category.includes('CWE-')) {
        const match = vuln.category.match(/CWE-(\d+)/);
        if (match) {
            cweId = parseInt(match[1], 10);
        }
    }

    if (cweId && !isCisaKev) {
        isCisaKev = await this.cisaService.isKnownExploitedCwe(cweId);
    }

    const exploitAvailable = await this.exploitService.hasPublicExploit(vuln.cve_id, cweId);

    const enrichment = this.correlationEngine.correlate(
      vuln,
      isCisaKev,
      exploitAvailable,
      cveDetails?.cvssV3Score,
    );

    return enrichment;
  }
}
