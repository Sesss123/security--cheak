import { spawn } from 'child_process';
import { db } from '../db/pool';
import { analyzeVulnerability, generateExecutiveSummary } from './ai.service';
import { CreateScanRequest, Scan, Vulnerability } from '../types';
import { wsManager } from './websocket.service';

const SCANNER_BIN = process.env.SCANNER_BIN ?? './scanner';

export async function createScan(
  userId: string,
  request: CreateScanRequest
): Promise<Scan> {
  const result = await db.query(
    `INSERT INTO scans (user_id, target_url, scan_types, options, status)
     VALUES ($1, $2, $3, $4, 'pending')
     RETURNING *`,
    [
      userId,
      request.target_url,
      request.scan_types,
      JSON.stringify(request.options ?? {}),
    ]
  );
  return result.rows[0];
}

export async function runScan(scanId: string): Promise<void> {
  // Mark as running
  await db.query(
    `UPDATE scans SET status='running', started_at=NOW() WHERE id=$1`,
    [scanId]
  );

  const scanRow = await db.query('SELECT * FROM scans WHERE id=$1', [scanId]);
  const scan: Scan = scanRow.rows[0];

  wsManager.broadcast(scan.id, { type: 'scan:started', scan_id: scanId, data: {}, timestamp: new Date().toISOString() });

  try {
    // Build CLI args for Rust scanner
    const args = [
      '--target', scan.target_url,
      '--scans', scan.scan_types.join(','),
      '--json',
    ];

    const rawResult = await runScannerProcess(scanId, args);

    // Store vulnerabilities
    const vulns: any[] = rawResult.vulnerabilities ?? [];
    for (const v of vulns) {
      await db.query(
        `INSERT INTO vulnerabilities
          (scan_id, title, description, severity, category, cvss_score,
           affected_url, affected_parameter, owasp_category, cwe_id,
           evidence, remediation)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          scanId, v.title, v.description,
          v.severity?.as_str ?? v.severity ?? 'INFO',
          v.category ?? null,
          v.cvss_score ?? 0,
          v.affected_url, v.affected_parameter ?? null,
          v.owasp_category ?? null, v.cwe_id ?? null,
          JSON.stringify(v.evidence ?? []),
          v.remediation ?? '',
        ]
      );

      wsManager.broadcast(scanId, {
        type: 'scan:vuln_found',
        scan_id: scanId,
        data: { title: v.title, severity: v.severity },
        timestamp: new Date().toISOString(),
      });
    }

    const summary = rawResult.summary ?? {};

    // Update scan with results
    await db.query(
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
      ]
    );

    // Kick off AI analysis in background
    enrichWithAI(scanId, scan.target_url).catch(console.error);

    wsManager.broadcast(scanId, {
      type: 'scan:completed',
      scan_id: scanId,
      data: summary,
      timestamp: new Date().toISOString(),
    });

  } catch (err: any) {
    await db.query(
      `UPDATE scans SET status='failed', error_message=$2 WHERE id=$1`,
      [scanId, err.message]
    );
    wsManager.broadcast(scanId, {
      type: 'scan:failed',
      scan_id: scanId,
      data: { error: err.message },
      timestamp: new Date().toISOString(),
    });
  }
}

// ── Run Rust binary ───────────────────────────────────────────
function runScannerProcess(scanId: string, args: string[]): Promise<any> {
  return new Promise((resolve, reject) => {
    const proc = spawn(SCANNER_BIN, args);
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', (d) => {
      stderr += d.toString();
      // Forward progress logs via WebSocket
      const lines = d.toString().split('\n').filter(Boolean);
      for (const line of lines) {
        wsManager.broadcast(scanId, {
          type: 'scan:progress',
          scan_id: scanId,
          data: { message: line },
          timestamp: new Date().toISOString(),
        });
      }
    });

    proc.on('close', (code) => {
      if (code !== 0) return reject(new Error(`Scanner exited with code ${code}: ${stderr}`));
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
async function enrichWithAI(scanId: string, targetUrl: string): Promise<void> {
  const vulnRows = await db.query(
    'SELECT * FROM vulnerabilities WHERE scan_id=$1 ORDER BY cvss_score DESC',
    [scanId]
  );
  const vulns: Vulnerability[] = vulnRows.rows;

  // Analyze each vulnerability with Claude (top 10 to avoid cost)
  for (const vuln of vulns.slice(0, 10)) {
    try {
      const analysis = await analyzeVulnerability(vuln, targetUrl);
      await db.query(
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
        ]
      );
    } catch (e) {
      console.error(`AI analysis failed for vuln ${vuln.id}:`, e);
    }
  }

  // Generate executive summary
  const scan = (await db.query('SELECT * FROM scans WHERE id=$1', [scanId])).rows[0];
  const summary = await generateExecutiveSummary(
    targetUrl,
    scan.total_vulns, scan.critical_count, scan.high_count,
    scan.medium_count, scan.low_count, parseFloat(scan.risk_score ?? '0'),
    vulns.slice(0, 5)
  );

  await db.query(
    `INSERT INTO reports (scan_id, user_id, title, executive_summary, risk_rating)
     VALUES ($1, $2, $3, $4, $5)`,
    [
      scanId, scan.user_id,
      `Security Report - ${targetUrl}`,
      summary.executive_summary,
      summary.risk_rating,
    ]
  );
}
