import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class CisaService {
  private readonly logger = new Logger(CisaService.name);

  // Hardcoded known exploited CWEs based on CISA KEV
  private readonly exploitedCwes = new Set([78, 79, 89, 94, 287, 798]);

  async isKnownExploitedCwe(cweId: number): Promise<boolean> {
    return this.exploitedCwes.has(cweId);
  }

  async isKnownExploitedCve(cveId: string): Promise<boolean> {
    // In production, this would query a cached local copy of the CISA KEV catalog
    this.logger.debug(`Checking if ${cveId} is in CISA KEV...`);
    return false; // Mock
  }
}
