import { Controller, Get, Req, Res, UseGuards, Inject } from '@nestjs/common';
import type { Response } from 'express';
import { DB_POOL } from '../db/database.module';
import { Pool } from 'pg';
import { AuthGuard } from '../auth/auth.guard';

@UseGuards(AuthGuard)
@Controller('api/analytics')
export class AnalyticsController {
  constructor(@Inject(DB_POOL) private db: Pool) {}

  @Get('overview')
  async getOverview(@Req() req: any, @Res() res: Response) {
    const userId = req.user.userId;

    const [totalScans, recentScans, vulnStats, topTargets] = await Promise.all([
      // Total scans
      this.db.query('SELECT COUNT(*) FROM scans WHERE user_id=$1', [userId]),

      // Recent scan trend (last 7 days)
      this.db.query(
        `SELECT DATE(created_at) as date, COUNT(*) as count
         FROM scans WHERE user_id=$1
         AND created_at > NOW() - INTERVAL '7 days'
         GROUP BY DATE(created_at) ORDER BY date`,
        [userId]
      ),

      // Vulnerability severity breakdown
      this.db.query(
        `SELECT v.severity, COUNT(*) as count
         FROM vulnerabilities v
         JOIN scans s ON s.id = v.scan_id
         WHERE s.user_id=$1
         GROUP BY v.severity`,
        [userId]
      ),

      // Most scanned targets
      this.db.query(
        `SELECT target_url, COUNT(*) as scan_count,
                MAX(risk_score) as max_risk
         FROM scans WHERE user_id=$1
         GROUP BY target_url
         ORDER BY scan_count DESC LIMIT 5`,
        [userId]
      ),
    ]);

    return res.json({
      total_scans: parseInt(totalScans.rows[0].count),
      scan_trend: recentScans.rows,
      vulnerability_breakdown: vulnStats.rows,
      top_targets: topTargets.rows,
    });
  }

  @Get('vulnerabilities')
  async getVulnerabilities(@Req() req: any, @Res() res: Response) {
    const userId = req.user.userId;

    const [byCategory, byOwasp, trend] = await Promise.all([
      this.db.query(
        `SELECT v.category, COUNT(*) as count
         FROM vulnerabilities v JOIN scans s ON s.id=v.scan_id
         WHERE s.user_id=$1 GROUP BY v.category ORDER BY count DESC LIMIT 10`,
        [userId]
      ),
      this.db.query(
        `SELECT v.owasp_category, COUNT(*) as count
         FROM vulnerabilities v JOIN scans s ON s.id=v.scan_id
         WHERE s.user_id=$1 AND v.owasp_category IS NOT NULL
         GROUP BY v.owasp_category ORDER BY count DESC`,
        [userId]
      ),
      this.db.query(
        `SELECT DATE(s.completed_at) as date,
                COUNT(v.id) as total_vulns,
                AVG(s.risk_score) as avg_risk
         FROM scans s LEFT JOIN vulnerabilities v ON v.scan_id=s.id
         WHERE s.user_id=$1 AND s.status='completed'
         AND s.completed_at > NOW() - INTERVAL '30 days'
         GROUP BY DATE(s.completed_at) ORDER BY date`,
        [userId]
      ),
    ]);

    return res.json({
      by_category: byCategory.rows,
      by_owasp: byOwasp.rows,
      trend_30_days: trend.rows,
    });
  }
}
