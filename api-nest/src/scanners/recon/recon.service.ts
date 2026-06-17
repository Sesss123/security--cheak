import { Injectable, Logger, Inject } from '@nestjs/common';
import { ScannerService } from '../../services/scanner.service';
import { DB_POOL } from '../../db/database.module';
import { Pool } from 'pg';

@Injectable()
export class ReconService {
  private readonly logger = new Logger(ReconService.name);

  constructor(
    private readonly scannerService: ScannerService,
    @Inject(DB_POOL) private readonly db: Pool,
  ) {}

  async triggerRecon(targetId: string, targetUrl: string): Promise<void> {
    this.logger.log(`Triggering Advanced Recon for target ${targetId}: ${targetUrl}`);
    
    // Delegate to the Rust scanner via ScannerService
    await this.scannerService.startScan({
      target_url: targetUrl,
      modules: ['technology_fingerprint', 'header_analysis', 'js_discovery', 'endpoint_discovery'],
      mode: 'recon', 
    }, targetId);
  }

  async saveReconData(targetId: string, reconData: any): Promise<void> {
    try {
      const query = `
        INSERT INTO "ReconData" (target_id, attack_surface_map, technology_stack, interesting_resources, recon_summary)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (target_id) DO UPDATE
        SET attack_surface_map = EXCLUDED.attack_surface_map,
            technology_stack = EXCLUDED.technology_stack,
            interesting_resources = EXCLUDED.interesting_resources,
            recon_summary = EXCLUDED.recon_summary,
            updated_at = NOW();
      `;
      await this.db.query(query, [
        targetId,
        JSON.stringify(reconData.attackSurfaceMap || {}),
        JSON.stringify(reconData.technologyStack || []),
        JSON.stringify(reconData.interestingResources || []),
        reconData.summary || '',
      ]);
      this.logger.debug(`Saved recon data for target: ${targetId}`);
    } catch (error) {
      this.logger.error(`Failed to save recon data: ${(error as Error).message}`);
    }
  }
}
