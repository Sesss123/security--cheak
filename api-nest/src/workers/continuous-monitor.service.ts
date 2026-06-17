import { Injectable, Logger, Inject } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ScannerService } from '../services/scanner.service';
import { DB_POOL } from '../db/database.module';
import { Pool } from 'pg';

@Injectable()
export class ContinuousMonitorService {
  private readonly logger = new Logger(ContinuousMonitorService.name);

  constructor(
    private readonly scannerService: ScannerService,
    @Inject(DB_POOL) private readonly db: Pool,
  ) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleDailyAssetMonitoring() {
    this.logger.log('Running scheduled continuous monitoring for assets...');
    try {
      // Fetch targets configured for continuous monitoring
      const res = await this.db.query('SELECT id, url FROM "Targets" WHERE "continuous_monitoring" = true');
      const targets = res.rows;

      for (const target of targets) {
        this.logger.log(`Triggering monitoring scan for ${target.url}`);
        // Here we could diff current state with baseline
        await this.scannerService.startScan({
          target_url: target.url,
          modules: ['continuous_monitor'],
          mode: 'monitor',
        } as any, target.id);
      }
    } catch (error) {
      this.logger.error(`Error during continuous monitoring: ${(error as Error).message}`);
    }
  }
}
