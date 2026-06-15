import { Injectable, Logger, Inject } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { Pool } from 'pg';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { DB_POOL } from '../db/database.module';
import { Scan } from '../types';

@Injectable()
export class MonitoringService {
  private readonly logger = new Logger(MonitoringService.name);

  constructor(
    @Inject(DB_POOL) private db: Pool,
    @InjectQueue('scan-jobs') private scanQueue: Queue,
  ) {}

  // Run automatically every midnight (can be changed to testing values like CronExpression.EVERY_MINUTE)
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async runDailyContinuousMonitoring() {
    this.logger.log('Starting daily continuous asset monitoring...');

    try {
      // Find all uniquely scanned target_urls in the last 30 days
      const result = await this.db.query(`
        SELECT DISTINCT target_url, user_id 
        FROM scans 
        WHERE created_at > NOW() - INTERVAL '30 days'
      `);

      const targets = result.rows;
      if (targets.length === 0) {
        this.logger.log('No recent targets found for monitoring.');
        return;
      }

      this.logger.log(`Found ${targets.length} assets to continuously monitor.`);

      for (const target of targets) {
        // Create a new scan record for monitoring
        const scanRes = await this.db.query(
          `INSERT INTO scans (user_id, target_url, scan_types, options, status)
           VALUES ($1, $2, $3, $4, 'pending') RETURNING *`,
          [
            target.user_id,
            target.target_url,
            ['port_scan', 'http_headers', 'security_headers'], // Run a quick periodic subset
            {
              rate_limit: 50,
              timeout_secs: 30,
              follow_redirects: true,
              max_depth: 2,
              port_range: 'Common'
            }
          ],
        );

        const newScan = scanRes.rows[0];

        // Dispatch to BullMQ worker
        await this.scanQueue.add('run_scan', {
          scanId: newScan.id,
          scan: newScan,
        });

        this.logger.log(`Dispatched monitoring scan job for ${target.target_url} (Scan ID: ${newScan.id})`);
      }
    } catch (err: any) {
      this.logger.error(`Error during continuous monitoring: ${err.message}`);
    }
  }
}
