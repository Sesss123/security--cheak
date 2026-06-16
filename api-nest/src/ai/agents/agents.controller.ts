import { Controller, Post, Body, Req, Res, UseGuards, Inject, HttpException, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { AuthGuard } from '../../auth/auth.guard';
import { DirectorService } from './director.service';
import { DB_POOL } from '../../db/database.module';
import { Pool } from 'pg';

@UseGuards(AuthGuard)
@Controller('api/ai/agents')
export class AgentsController {
  constructor(
    private readonly directorService: DirectorService,
    @Inject(DB_POOL) private db: Pool
  ) {}

  @Post('analyze')
  async runAnalysis(@Req() req: any, @Body() body: { scanId: string }, @Res() res: Response) {
    const userId = req.user.userId;
    const { scanId } = body;

    if (!scanId) {
      throw new HttpException('scanId is required', HttpStatus.BAD_REQUEST);
    }

    // Verify scan belongs to user and get target URL
    const scanResult = await this.db.query(
      'SELECT id, target_url FROM scans WHERE id=$1 AND user_id=$2',
      [scanId, userId]
    );

    if (scanResult.rows.length === 0) {
      throw new HttpException('Scan not found', HttpStatus.NOT_FOUND);
    }

    const targetUrl = scanResult.rows[0].target_url;

    // Get vulnerabilities for this scan
    const vulnsResult = await this.db.query(
      'SELECT * FROM vulnerabilities WHERE scan_id=$1',
      [scanId]
    );

    const rawVulns = vulnsResult.rows;

    if (rawVulns.length === 0) {
      return res.json({ message: 'No vulnerabilities found to analyze.', payload: null });
    }

    try {
      // Run the Multi-Agent pipeline
      const payload = await this.directorService.runSecurityAnalysis(targetUrl, scanId, rawVulns);

      return res.json({
        message: 'Analysis complete',
        payload
      });
    } catch (error) {
      throw new HttpException('AI Analysis failed', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
