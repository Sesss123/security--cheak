import { Controller, Get, Post, Delete, Param, Query, Body, Req, Res, HttpStatus, UseGuards, Inject } from '@nestjs/common';
import type { Request, Response } from 'express';
import { z } from 'zod';
import { DB_POOL } from '../db/database.module';
import { Pool } from 'pg';
import { AuthGuard } from '../auth/auth.guard';
import { ScannerService } from '../services/scanner.service';
import { AiService } from '../services/ai.service';
import { ScanGateway } from '../gateways/scan.gateway';
import { SmartWebService } from '../scanners/smart-web/smart-web.service';

const CreateScanSchema = z.object({
  target_url: z.string().url(),
  scan_types: z.array(z.string()).min(1),
  options: z.object({
    rate_limit: z.number().min(1).max(50).default(10),
    timeout_secs: z.number().min(5).max(120).default(30),
    port_range: z.enum(['Common', 'Extended', 'Full']).default('Common'),
    follow_redirects: z.boolean().default(true),
    max_depth: z.number().min(1).max(10).default(3),
  }).optional(),
});

@UseGuards(AuthGuard)
@Controller('api/scans')
export class ScanController {
  constructor(
    @Inject(DB_POOL) private db: Pool,
    private scannerService: ScannerService,
    private aiService: AiService,
    private scanGateway: ScanGateway,
    private smartWebService: SmartWebService,
  ) {}

  // [HIGH] SSRF Protection: Check if hostname is internal/private
  private isPrivateHost(targetUrl: string): boolean {
    try {
      const url = new URL(targetUrl);
      const host = url.hostname;
      if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true;
      if (host.startsWith('10.')) return true;
      if (host.startsWith('192.168.')) return true;
      if (host.startsWith('169.254.')) return true; // AWS Metadata
      // 172.16.x.x - 172.31.x.x
      if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)) return true;
      return false;
    } catch {
      return true; // invalid url = treat as unsafe
    }
  }

  @Post()
  async createScan(@Body() bodyData: any, @Req() req: any, @Res() res: Response) {
    try {
      const body = CreateScanSchema.parse(bodyData);

      if (this.isPrivateHost(body.target_url)) {
        return res.status(HttpStatus.FORBIDDEN).json({ error: 'Scanning private or internal IP addresses is not allowed.' });
      }

      const scan = await this.scannerService.createScan(req.user.userId, body as any);

      // [LOW] Audit Logging
      await this.db.query(
        `INSERT INTO scan_audit_logs (user_id, scan_id, target_url, action, ip_address)
         VALUES ($1, $2, $3, 'CREATE_SCAN', $4)`,
        [req.user.userId, scan.id, body.target_url, req.ip]
      ).catch(console.error);

      // Run scan async (don't await)
      this.scannerService.runScan(scan.id).catch(console.error);

      return res.status(HttpStatus.ACCEPTED).json(scan);
    } catch (err: any) {
      if (err.name === 'ZodError') return res.status(HttpStatus.BAD_REQUEST).json({ error: err.errors });
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ error: 'Failed to create scan' });
    }
  }

  @Post('smart')
  async createSmartScan(@Body() bodyData: any, @Req() req: any, @Res() res: Response) {
    try {
      const { target_url, framework } = bodyData;
      if (!target_url) {
        return res.status(HttpStatus.BAD_REQUEST).json({ error: 'Target URL is required' });
      }
      const fwLower = framework?.toLowerCase();
      if (!fwLower || !['wordpress', 'laravel'].includes(fwLower)) {
        return res.status(HttpStatus.BAD_REQUEST).json({ error: 'Framework must be wordpress or laravel' });
      }

      if (this.isPrivateHost(target_url)) {
        return res.status(HttpStatus.FORBIDDEN).json({ error: 'Scanning private or internal IP addresses is not allowed.' });
      }

      const scan = await this.smartWebService.triggerSmartScan(req.user.userId, target_url, fwLower);

      // Audit Logging
      await this.db.query(
        `INSERT INTO scan_audit_logs (user_id, scan_id, target_url, action, ip_address)
         VALUES ($1, $2, $3, 'CREATE_SMART_SCAN', $4)`,
        [req.user.userId, scan.id, target_url, req.ip]
      ).catch(console.error);

      return res.status(HttpStatus.ACCEPTED).json(scan);
    } catch (err: any) {
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ error: 'Failed to create smart scan' });
    }
  }

  @Get()
  async getScans(@Query('page') queryPage: string, @Query('limit') queryLimit: string, @Req() req: any, @Res() res: Response) {
    const page  = parseInt(queryPage) || 1;
    const limit = Math.min(parseInt(queryLimit) || 20, 200);
    const offset = (page - 1) * limit;

    const result = await this.db.query(
      `SELECT id, target_url, status, risk_score, total_vulns,
              critical_count, high_count, medium_count, low_count,
              started_at, completed_at, created_at
       FROM scans
       WHERE user_id=$1
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.userId, limit, offset]
    );

    const count = await this.db.query(
      'SELECT COUNT(*) FROM scans WHERE user_id=$1',
      [req.user.userId]
    );

    return res.json({
      scans: result.rows,
      total: parseInt(count.rows[0].count),
      page,
      limit,
    });
  }

  @Get(':id')
  async getScanDetails(@Param('id') id: string, @Req() req: any, @Res() res: Response) {
    const result = await this.db.query(
      'SELECT * FROM scans WHERE id=$1 AND user_id=$2',
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(HttpStatus.NOT_FOUND).json({ error: 'Scan not found' });
    }

    return res.json(result.rows[0]);
  }

  @Get(':id/vulnerabilities')
  async getVulnerabilities(@Param('id') id: string, @Query('severity') severity: string, @Query('page') queryPage: string, @Query('limit') queryLimit: string, @Req() req: any, @Res() res: Response) {
    const page  = parseInt(queryPage) || 1;
    const limit = Math.min(parseInt(queryLimit) || 50, 200);
    const offset = (page - 1) * limit;
    // Verify ownership
    const scan = await this.db.query(
      'SELECT id FROM scans WHERE id=$1 AND user_id=$2',
      [id, req.user.userId]
    );
    if (scan.rows.length === 0) {
      return res.status(HttpStatus.NOT_FOUND).json({ error: 'Scan not found' });
    }

    const conditions = ['scan_id=$1'];
    const params: any[] = [id];

    if (severity) {
      conditions.push(`severity=$${params.length + 1}`);
      params.push(severity.toUpperCase());
    }

    const result = await this.db.query(
      `SELECT * FROM vulnerabilities
       WHERE ${conditions.join(' AND ')}
       ORDER BY cvss_score DESC, severity
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset]
    );

    const count = await this.db.query(
      `SELECT COUNT(*) FROM vulnerabilities WHERE ${conditions.join(' AND ')}`,
      params
    );

    return res.json({
      vulnerabilities: result.rows,
      total: parseInt(count.rows[0].count),
      page,
      limit
    });
  }

  @Get(':id/report')
  async getReport(@Param('id') id: string, @Req() req: any, @Res() res: Response) {
    const scan = await this.db.query(
      'SELECT id FROM scans WHERE id=$1 AND user_id=$2',
      [id, req.user.userId]
    );
    if (scan.rows.length === 0) {
      return res.status(HttpStatus.NOT_FOUND).json({ error: 'Scan not found' });
    }

    const report = await this.db.query(
      'SELECT * FROM reports WHERE scan_id=$1 ORDER BY generated_at DESC LIMIT 1',
      [id]
    );

    if (report.rows.length === 0) {
      return res.status(HttpStatus.NOT_FOUND).json({ error: 'Report not ready yet' });
    }

    return res.json(report.rows[0]);
  }

  @Post(':id/chat')
  async chatAboutScan(@Param('id') id: string, @Body() body: any, @Req() req: any, @Res() res: Response) {
    const { message, history = [] } = body;

    if (!message) return res.status(HttpStatus.BAD_REQUEST).json({ error: 'message required' });

    const scan = await this.db.query(
      'SELECT id FROM scans WHERE id=$1 AND user_id=$2',
      [id, req.user.userId]
    );
    if (scan.rows.length === 0) {
      return res.status(HttpStatus.NOT_FOUND).json({ error: 'Scan not found' });
    }

    const vulns = await this.db.query(
      'SELECT title, severity, category FROM vulnerabilities WHERE scan_id=$1',
      [id]
    );

    const reply = await this.aiService.chatAboutScan(
      id,
      vulns.rows,
      message,
      history
    );

    return res.json({ reply });
  }

  @Delete(':id')
  async deleteScan(@Param('id') id: string, @Req() req: any, @Res() res: Response) {
    const result = await this.db.query(
      'DELETE FROM scans WHERE id=$1 AND user_id=$2 RETURNING id',
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(HttpStatus.NOT_FOUND).json({ error: 'Scan not found' });
    }

    // [MEDIUM] Connection Cleanup
    this.scanGateway.closeScanConnections(id);

    return res.json({ deleted: true });
  }
}
