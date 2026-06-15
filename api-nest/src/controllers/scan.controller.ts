import { Controller, Get, Post, Delete, Param, Query, Body, Req, Res, HttpStatus, UseGuards, Inject } from '@nestjs/common';
import type { Request, Response } from 'express';
import { z } from 'zod';
import { DB_POOL } from '../db/database.module';
import { Pool } from 'pg';
import { AuthGuard } from '../auth/auth.guard';
import { ScannerService } from '../services/scanner.service';
import { AiService } from '../services/ai.service';

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
  ) {}

  @Post()
  async createScan(@Body() bodyData: any, @Req() req: any, @Res() res: Response) {
    try {
      const body = CreateScanSchema.parse(bodyData);
      const scan = await this.scannerService.createScan(req.user.userId, body as any);

      // Run scan async (don't await)
      this.scannerService.runScan(scan.id).catch(console.error);

      return res.status(HttpStatus.ACCEPTED).json(scan);
    } catch (err: any) {
      if (err.name === 'ZodError') return res.status(HttpStatus.BAD_REQUEST).json({ error: err.errors });
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ error: 'Failed to create scan' });
    }
  }

  @Get()
  async getScans(@Query('page') queryPage: string, @Query('limit') queryLimit: string, @Req() req: any, @Res() res: Response) {
    const page  = parseInt(queryPage) || 1;
    const limit = parseInt(queryLimit) || 20;
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
  async getVulnerabilities(@Param('id') id: string, @Query('severity') severity: string, @Req() req: any, @Res() res: Response) {
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
       ORDER BY cvss_score DESC, severity`,
      params
    );

    return res.json(result.rows);
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

    return res.json({ deleted: true });
  }
}
