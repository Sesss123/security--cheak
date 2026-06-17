import { Injectable, Logger, Inject } from '@nestjs/common';
import { AssetDiscoveryDto, DiscoveredAsset, TechnologyAsset } from './dto/asset.dto';
import { ScannerService } from '../../services/scanner.service';
import { DB_POOL } from '../../db/database.module';
import { Pool } from 'pg';

@Injectable()
export class AssetDiscoveryService {
  private readonly logger = new Logger(AssetDiscoveryService.name);

  constructor(
    private readonly scannerService: ScannerService,
    @Inject(DB_POOL) private readonly db: Pool,
  ) {}

  async triggerDiscovery(targetId: string, payload: AssetDiscoveryDto): Promise<void> {
    this.logger.log(`Triggering asset discovery for target ${targetId}: ${payload.targetUrl}`);
    
    // Delegate to the Rust scanner via ScannerService
    // We pass the specific modules requested (dns, ports, etc.)
    await this.scannerService.startScan({
      target_url: payload.targetUrl,
      modules: payload.modules || ['dns', 'ports'],
      // We encode the mode so the Rust engine knows to use asset discovery logic
      mode: 'asset_discovery', 
    }, targetId);
  }

  async saveDiscoveredAsset(asset: DiscoveredAsset): Promise<void> {
    try {
      const query = `
        INSERT INTO "AssetInventory" (target_id, asset_type, value, metadata, discovered_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (target_id, asset_type, value) DO UPDATE
        SET metadata = EXCLUDED.metadata, discovered_at = EXCLUDED.discovered_at;
      `;
      await this.db.query(query, [
        asset.targetId,
        asset.assetType,
        asset.value,
        asset.metadata ? JSON.stringify(asset.metadata) : null,
        asset.discoveredAt,
      ]);
      this.logger.debug(`Saved asset: ${asset.assetType} - ${asset.value}`);
    } catch (error) {
      this.logger.error(`Failed to save asset: ${(error as Error).message}`);
    }
  }

  async saveTechnologyAsset(asset: TechnologyAsset): Promise<void> {
    try {
      const query = `
        INSERT INTO "TechnologyInventory" (target_id, technology, version, category, confidence)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (target_id, technology) DO UPDATE
        SET version = EXCLUDED.version, confidence = EXCLUDED.confidence;
      `;
      await this.db.query(query, [
        asset.targetId,
        asset.technology,
        asset.version || null,
        asset.category,
        asset.confidence,
      ]);
      this.logger.debug(`Saved technology: ${asset.technology} (${asset.version})`);
    } catch (error) {
      this.logger.error(`Failed to save technology asset: ${(error as Error).message}`);
    }
  }
}
