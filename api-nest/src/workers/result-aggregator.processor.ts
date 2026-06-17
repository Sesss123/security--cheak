import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger, Inject } from '@nestjs/common';
import { Pool } from 'pg';
import { DB_POOL } from '../db/database.module';
import { AiService } from '../services/ai.service';
import { RagService } from '../services/rag.service';
import { ThreatIntelService } from '../services/threat-intel.service';
import { AlertService } from '../services/alert.service';
import { ScanGateway } from '../gateways/scan.gateway';
import { Vulnerability } from '../types';

@Processor('scan-results')
export class ResultAggregatorProcessor extends WorkerHost {
  private readonly logger = new Logger(ResultAggregatorProcessor.name);

  constructor(
    @Inject(DB_POOL) private db: Pool,
    private aiService: AiService,
    private ragService: RagService,
    private threatIntelService: ThreatIntelService,
    private alertService: AlertService,
    private scanGateway: ScanGateway,
  ) {
    super();
  }

  async process(job: Job<any, any, string>): Promise<any> {
    if (job.name === 'scan_completed') {
      await this.handleScanCompleted(job.data);
    } else if (job.name === 'scan_failed') {
      await this.handleScanFailed(job.data);
    } else if (job.name === 'scan_progress') {
      await this.handleScanProgress(job.data);
    }
  }

  private async handleScanProgress(data: { scanId: string; message: string }) {
    this.scanGateway.broadcast(data.scanId, {
      type: 'scan:progress',
      scan_id: data.scanId,
      data: { message: data.message },
      timestamp: new Date().toISOString(),
    });
  }

  private async handleScanFailed(data: { scanId: string; error: string }) {
    this.logger.error(`Scan ${data.scanId} failed: ${data.error}`);
    await this.db.query(
      `UPDATE scans SET status='failed', error_message=$2 WHERE id=$1`,
      [data.scanId, data.error],
    );
    this.scanGateway.broadcast(data.scanId, {
      type: 'scan:failed',
      scan_id: data.scanId,
      data: { error: data.error },
      timestamp: new Date().toISOString(),
    });
  }

  private async handleScanCompleted(data: { scanId: string; scan: any; rawResult: any }) {
    const { scanId, scan, rawResult } = data;
    this.logger.log(`Aggregating results for scan ${scanId}`);

    // This contains all the DB and AI logic previously in ScannerWorker
    const vulns: any[] = rawResult.vulnerabilities ?? [];
    for (const v of vulns) {
      // [FIXED] Issue #8: Rust serialises Severity as Title-case ("High", "Critical") but
      // the DB schema and filtered queries expect UPPERCASE ("HIGH", "CRITICAL").
      // The old code used v.severity?.as_str which is a Rust method — always undefined in JS.
      let severity = (v.severity ?? 'INFO').toString().toUpperCase();

      
      const threatIntel = await this.threatIntelService.enrichVulnerability({
        title: v.title,
        description: v.description,
        severity: severity,
        cvss_score: v.cvss_score ?? 0,
      } as any);

      const finalCvss = Math.max(v.cvss_score ?? 0, threatIntel.threat_score);

      const result = await this.db.query(
        `INSERT INTO vulnerabilities
          (scan_id, title, description, severity, category, cvss_score,
           affected_url, affected_parameter, owasp_category, cwe_id,
           evidence, remediation, cve_id, exploit_available)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
        [
          scanId, v.title, v.description, severity, v.category ?? null, finalCvss,
          v.affected_url, v.affected_parameter ?? null, v.owasp_category ?? null,
          v.cwe_id ?? null, JSON.stringify(v.evidence ?? []), v.remediation ?? '',
          threatIntel.cve_id, threatIntel.exploit_available,
        ],
      );
      const insertedVuln = result.rows[0];

      this.ragService.ingestVulnerability(insertedVuln).catch(e => 
        this.logger.error(`Failed to ingest to RAG`, e)
      );

      this.scanGateway.broadcast(scanId, {
        type: 'scan:vuln_found',
        scan_id: scanId,
        data: { title: v.title, severity: severity },
        timestamp: new Date().toISOString(),
      });
    }

    const summary = rawResult.summary ?? {};

    await this.db.query(
      `UPDATE scans SET
         status='completed', completed_at=NOW(),
         risk_score=$2, total_vulns=$3,
         critical_count=$4, high_count=$5, medium_count=$6,
         low_count=$7, info_count=$8, raw_result=$9
       WHERE id=$1`,
      [
        scanId, summary.risk_score ?? 0, summary.total_vulnerabilities ?? 0,
        summary.critical ?? 0, summary.high ?? 0, summary.medium ?? 0,
        summary.low ?? 0, summary.info ?? 0, JSON.stringify(rawResult),
      ],
    );

    this.enrichWithAI(scanId, scan.target_url).catch((e) =>
      this.logger.error(e),
    );

    const criticalCount = summary.critical ?? 0;
    const highCount = summary.high ?? 0;
    if (criticalCount > 0 || highCount > 0) {
      this.alertService.sendAlert(
        `Vulnerabilities Found on ${scan.target_url}`,
        `Scan completed with ${criticalCount} Critical and ${highCount} High vulnerabilities. Please review the dashboard immediately.`,
        criticalCount > 0 ? 'CRITICAL' : 'HIGH'
      ).catch(e => this.logger.error('Failed to dispatch alert', e));
    }

    this.scanGateway.broadcast(scanId, {
      type: 'scan:completed',
      scan_id: scanId,
      data: summary,
      timestamp: new Date().toISOString(),
    });
  }

  private async enrichWithAI(scanId: string, targetUrl: string): Promise<void> {
    const vulnRows = await this.db.query(
      'SELECT * FROM vulnerabilities WHERE scan_id=$1 ORDER BY cvss_score DESC',
      [scanId],
    );
    const vulns: Vulnerability[] = vulnRows.rows;

    const limit = Number(process.env.AI_ANALYSIS_LIMIT) || 10;
    const toAnalyze = vulns.slice(0, limit);

    /**
     * [FIX #31] Previously: serial for-loop — N vulns = N sequential API calls.
     * N=10 vulns at ~2s each = 20s total; N=20 = 40s.
     *
     * Now: batched parallel execution with CONCURRENCY = 3.
     * Chunks of 3 are processed simultaneously, then the next chunk starts.
     * This keeps API pressure manageable while cutting wall-clock time by ~3×.
     */
    const CONCURRENCY = 3;
    for (let i = 0; i < toAnalyze.length; i += CONCURRENCY) {
      const batch = toAnalyze.slice(i, i + CONCURRENCY);

      // Run this batch in parallel; allSettled never throws on individual errors
      const results = await Promise.allSettled(
        batch.map(vuln => this.aiService.analyzeVulnerability(vuln, targetUrl)),
      );

      // Persist each result regardless of others succeeding or failing
      for (let j = 0; j < batch.length; j++) {
        const vuln   = batch[j];
        const result = results[j];

        if (result.status === 'fulfilled') {
          const analysis = result.value;
          await this.db.query(
            `UPDATE vulnerabilities SET
               ai_explanation=$2, ai_business_impact=$3,
               ai_remediation_steps=$4, ai_code_example=$5, fix_priority=$6,
               attack_path=$7, attack_probability=$8
             WHERE id=$1`,
            [
              vuln.id, analysis.explanation, analysis.business_impact,
              JSON.stringify(analysis.remediation_steps), analysis.code_example,
              analysis.fix_priority, JSON.stringify(analysis.attack_path || []),
              analysis.attack_probability || 'MEDIUM',
            ],
          );
        } else {
          this.logger.error(`AI analysis failed for vuln ${vuln.id}: ${result.reason}`);
        }
      }
    }

    const scan = (
      await this.db.query('SELECT * FROM scans WHERE id=$1', [scanId])
    ).rows[0];
    const summary = await this.aiService.generateExecutiveSummary(
      targetUrl, scan.total_vulns, scan.critical_count, scan.high_count,
      scan.medium_count, scan.low_count, parseFloat(scan.risk_score ?? '0'),
      vulns.slice(0, 5),
    );

    await this.db.query(
      `INSERT INTO reports (scan_id, user_id, title, executive_summary, risk_rating)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        scanId, scan.user_id, `Security Report - ${targetUrl}`,
        summary.executive_summary, summary.risk_rating,
      ],
    );
  }
}
