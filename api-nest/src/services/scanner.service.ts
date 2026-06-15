import { Injectable, Inject, Logger } from '@nestjs/common';
import { Pool } from 'pg';
import { CreateScanRequest, Scan } from '../types';
import { DB_POOL } from '../db/database.module';
import { ClientProxy } from '@nestjs/microservices';
import { ScanGateway } from '../gateways/scan.gateway';

@Injectable()
export class ScannerService {
  private readonly logger = new Logger(ScannerService.name);

  constructor(
    @Inject(DB_POOL) private db: Pool,
    @Inject('SCANNER_SERVICE') private rabbitClient: ClientProxy,
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
    
    // Emit job to RabbitMQ queue 'scan_queue'
    this.rabbitClient.emit('run_scan', { scanId, scan });

    this.scanGateway.broadcast(scan.id, {
      type: 'scan:started',
      scan_id: scanId,
      data: { message: 'Scan queued successfully' },
      timestamp: new Date().toISOString(),
    });
  }
}

