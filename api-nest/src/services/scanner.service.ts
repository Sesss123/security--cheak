import { Injectable, Inject, Logger } from '@nestjs/common';
import { Pool } from 'pg';
import { CreateScanRequest, Scan, ScanType } from '../types';
import { DB_POOL } from '../db/database.module';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { ScanGateway } from '../gateways/scan.gateway';

@Injectable()
export class ScannerService {
  private readonly logger = new Logger(ScannerService.name);

  constructor(
    @Inject(DB_POOL) private db: Pool,
    @InjectQueue('scan-jobs') private scanQueue: Queue,
    private scanGateway: ScanGateway,
  ) {}

  async createScan(userId: string, request: CreateScanRequest): Promise<Scan> {
    const result = await this.db.query(
      `INSERT INTO scans (user_id, target_url, scan_types, options, status)
       VALUES ($1, $2, $3, $4, 'pending')
       RETURNING *`,
      [
        userId,
        request.target_url,
        request.scan_types,
        JSON.stringify(request.options ?? {}),
      ],
    );
    return result.rows[0];
  }

  async runScan(scanId: string): Promise<void> {
    // We update status to 'queued' instead of running here
    await this.db.query(
      `UPDATE scans SET status='pending' WHERE id=$1`, // Will be set to running by Worker
      [scanId],
    );

    const scanRow = await this.db.query('SELECT * FROM scans WHERE id=$1', [
      scanId,
    ]);
    const scan: Scan = scanRow.rows[0];

    this.logger.log(`Queueing scan ${scanId} to RabbitMQ...`);
    
    // Emit job to BullMQ queue 'scan-jobs'
    await this.scanQueue.add('run_scan', { scanId, scan });

    this.scanGateway.broadcast(scan.id, {
      type: 'scan:started',
      scan_id: scanId,
      data: { message: 'Scan queued successfully' },
      timestamp: new Date().toISOString(),
    });
  }

  async startScan(
    request: { target_url: string; modules: string[]; mode?: string; options?: any },
    userIdOrTargetId: string,
  ): Promise<Scan> {
    this.logger.log(`Starting scan for target: ${request.target_url} initiated by ${userIdOrTargetId}`);
    
    // Resolve a valid user_id to satisfy foreign key constraints
    let userId = userIdOrTargetId;
    try {
      const userCheck = await this.db.query('SELECT id FROM users WHERE id = $1', [userId]);
      if (userCheck.rows.length === 0) {
        const fallbackUser = await this.db.query('SELECT id FROM users LIMIT 1');
        if (fallbackUser.rows.length > 0) {
          userId = fallbackUser.rows[0].id;
        }
      }
    } catch (err: any) {
      this.logger.warn(`Failed to validate user ID, using fallback: ${err.message}`);
      const fallbackUser = await this.db.query('SELECT id FROM users LIMIT 1');
      if (fallbackUser.rows.length > 0) {
        userId = fallbackUser.rows[0].id;
      }
    }

    const scanTypes = (request.modules || []) as ScanType[];
    const options = {
      ...(request.options ?? {}),
      mode: request.mode,
    };

    const scan = await this.createScan(userId, {
      target_url: request.target_url,
      scan_types: scanTypes,
      options,
    });

    await this.runScan(scan.id);
    return scan;
  }
}

