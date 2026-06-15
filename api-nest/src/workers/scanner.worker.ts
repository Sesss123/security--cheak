import { Controller, Logger, Inject } from '@nestjs/common';
import { EventPattern, Payload, Ctx, RmqContext } from '@nestjs/microservices';
import { Pool } from 'pg';
import { spawn } from 'child_process';
import { DB_POOL } from '../db/database.module';
import { AiService } from '../services/ai.service';
import { RagService } from '../services/rag.service';
import { ThreatIntelService } from '../services/threat-intel.service';
import { ScanGateway } from '../gateways/scan.gateway';
import { Scan, Vulnerability } from '../types';

@Controller()
export class ScannerWorker {
  private readonly logger = new Logger(ScannerWorker.name);
  private readonly SCANNER_BIN = process.env.SCANNER_BIN ?? '../scanner/target/release/scanner.exe';

  constructor(
    @Inject(DB_POOL) private db: Pool,
    private aiService: AiService,
    private ragService: RagService,
    private threatIntelService: ThreatIntelService,
    private scanGateway: ScanGateway,
  ) {}

  @EventPattern('run_scan')
  async handleRunScan(@Payload() data: { scanId: string, scan: Scan }, @Ctx() context: RmqContext) {
    const channel = context.getChannelRef();
    const originalMsg = context.getMessage();
    const { scanId, scan } = data;

    this.logger.log(`Worker received scan job for ID: ${scanId}`);

    try {
      // Mark as running
      await this.db.query(
        `UPDATE scans SET status='running', started_at=NOW() WHERE id=$1`,
        [scanId],
      );

      // Build CLI args for Rust scanner
      const args = [
        '--target',
        scan.target_url,
        '--scans',
        scan.scan_types.join(','),
        '--json',
      ];

      const rawResult = await this.runScannerProcess(scanId, args);

      const vulns: any[] = rawResult.vulnerabilities ?? [];
      for (const v of vulns) {
        let severity = v.severity?.as_str ?? v.severity ?? 'INFO';
        
        // 1. Fetch Threat Intelligence (NVD / Exploit DB)
        const threatIntel = await this.threatIntelService.enrichVulnerability({
          title: v.title,
          description: v.description,
          severity: severity,
          cvss_score: v.cvss_score ?? 0,
        } as any);

        // Update CVSS based on threat score if it is higher
        const finalCvss = Math.max(v.cvss_score ?? 0, threatIntel.threat_score);

        const result = await this.db.query(
          `INSERT INTO vulnerabilities
            (scan_id, title, description, severity, category, cvss_score,
             affected_url, affected_parameter, owasp_category, cwe_id,
             evidence, remediation, cve_id, exploit_available)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
          [
            scanId,
            v.title,
            v.description,
            severity,
            v.category ?? null,
            finalCvss,
            v.affected_url,
            v.affected_parameter ?? null,
            v.owasp_category ?? null,
            v.cwe_id ?? null,
            JSON.stringify(v.evidence ?? []),
            v.remediation ?? '',
            threatIntel.cve_id,
            threatIntel.exploit_available,
          ],
        );
        const insertedVuln = result.rows[0];

        // Ingest into Vector DB for AI RAG
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

      // Update scan with results
      await this.db.query(
        `UPDATE scans SET
           status='completed', completed_at=NOW(),
           risk_score=$2, total_vulns=$3,
           critical_count=$4, high_count=$5, medium_count=$6,
           low_count=$7, info_count=$8, raw_result=$9
         WHERE id=$1`,
        [
          scanId,
          summary.risk_score ?? 0,
          summary.total_vulnerabilities ?? 0,
          summary.critical ?? 0,
          summary.high ?? 0,
          summary.medium ?? 0,
          summary.low ?? 0,
          summary.info ?? 0,
          JSON.stringify(rawResult),
        ],
      );

      // Kick off AI analysis in background
      this.enrichWithAI(scanId, scan.target_url).catch((e) =>
        this.logger.error(e),
      );

      this.scanGateway.broadcast(scanId, {
        type: 'scan:completed',
        scan_id: scanId,
        data: summary,
        timestamp: new Date().toISOString(),
      });

    } catch (err: any) {
      this.logger.error(`Scan ${scanId} failed: ${err.message}`);
      await this.db.query(
        `UPDATE scans SET status='failed', error_message=$2 WHERE id=$1`,
        [scanId, err.message],
      );
      this.scanGateway.broadcast(scanId, {
        type: 'scan:failed',
        scan_id: scanId,
        data: { error: err.message },
        timestamp: new Date().toISOString(),
      });
    } finally {
      // Acknowledge the message so it's removed from queue
      channel.ack(originalMsg);
    }
  }

  // ── Run Rust binary ───────────────────────────────────────────
  private runScannerProcess(scanId: string, args: string[]): Promise<any> {
    return new Promise((resolve, reject) => {
      const proc = spawn(this.SCANNER_BIN, args);
      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (d) => {
        stdout += d.toString();
      });
      proc.stderr.on('data', (d) => {
        stderr += d.toString();
        // Forward progress logs via WebSocket
        const lines = d.toString().split('\n').filter(Boolean);
        for (const line of lines) {
          this.scanGateway.broadcast(scanId, {
            type: 'scan:progress',
            scan_id: scanId,
            data: { message: line },
            timestamp: new Date().toISOString(),
          });
        }
      });

      proc.on('close', (code) => {
        if (code !== 0)
          return reject(
            new Error(`Scanner exited with code ${code}: ${stderr}`),
          );
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(new Error('Failed to parse scanner output'));
        }
      });

      proc.on('error', reject);
    });
  }

  // ── AI Enrichment ─────────────────────────────────────────────
  private async enrichWithAI(scanId: string, targetUrl: string): Promise<void> {
    const vulnRows = await this.db.query(
      'SELECT * FROM vulnerabilities WHERE scan_id=$1 ORDER BY cvss_score DESC',
      [scanId],
    );
    const vulns: Vulnerability[] = vulnRows.rows;

    // Analyze each vulnerability with Claude (top 10 to avoid cost)
    for (const vuln of vulns.slice(0, 10)) {
      try {
        const analysis = await this.aiService.analyzeVulnerability(
          vuln,
          targetUrl,
        );
        await this.db.query(
          `UPDATE vulnerabilities SET
             ai_explanation=$2, ai_business_impact=$3,
             ai_remediation_steps=$4, ai_code_example=$5, fix_priority=$6
           WHERE id=$1`,
          [
            vuln.id,
            analysis.explanation,
            analysis.business_impact,
            JSON.stringify(analysis.remediation_steps),
            analysis.code_example,
            analysis.fix_priority,
          ],
        );
      } catch (e) {
        this.logger.error(`AI analysis failed for vuln ${vuln.id}:`, e);
      }
    }

    // Generate executive summary
    const scan = (
      await this.db.query('SELECT * FROM scans WHERE id=$1', [scanId])
    ).rows[0];
    const summary = await this.aiService.generateExecutiveSummary(
      targetUrl,
      scan.total_vulns,
      scan.critical_count,
      scan.high_count,
      scan.medium_count,
      scan.low_count,
      parseFloat(scan.risk_score ?? '0'),
      vulns.slice(0, 5),
    );

    await this.db.query(
      `INSERT INTO reports (scan_id, user_id, title, executive_summary, risk_rating)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        scanId,
        scan.user_id,
        `Security Report - ${targetUrl}`,
        summary.executive_summary,
        summary.risk_rating,
      ],
    );
  }
}
