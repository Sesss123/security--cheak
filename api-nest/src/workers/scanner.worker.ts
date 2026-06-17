import { Processor, WorkerHost, InjectQueue } from '@nestjs/bullmq';
import { Job, Queue } from 'bullmq';
import { Logger, Inject } from '@nestjs/common';
import { spawn } from 'child_process';
import SwaggerParser from '@apidevtools/swagger-parser';
import { Scan } from '../types';
import { Pool } from 'pg';
import { DB_POOL } from '../db/database.module';

@Processor('scan-jobs')
export class ScannerWorker extends WorkerHost {
  private readonly logger = new Logger(ScannerWorker.name);
  
  // [FIXED] Issue #5: Original whitelist rejected any path not matching two hard-coded strings,
  // silently falling back to a default that may not exist (ENOENT). Replaced with a
  // safe character-set regex that allows any conventional absolute or relative path.
  private getScannerBin(): string {
    const defaultBin =
      process.env.NODE_ENV === 'production'
        ? '/scanner/scanner'
        : '../scanner/target/release/scanner.exe';
    const envBin = process.env.SCANNER_BIN;
    if (envBin) {
      // Allow letters, digits, slashes, dots, hyphens, underscores only
      const safePath = /^[\w\/\.\-]+$/.test(envBin);
      if (!safePath) {
        this.logger.warn(`SCANNER_BIN contains unsafe characters: ${envBin}. Using default.`);
        return defaultBin;
      }
      return envBin;
    }
    return defaultBin;
  }
  private readonly SCANNER_BIN = this.getScannerBin();

  constructor(
    @InjectQueue('scan-results') private resultQueue: Queue,
    @Inject(DB_POOL) private db: Pool,
  ) {
    super();
  }

  async process(job: Job<{ scanId: string; scan: Scan }, any, string>): Promise<any> {
    const { scanId, scan } = job.data;
    this.logger.log(`Worker processing scan job for ID: ${scanId}`);

    // Mark the scan as 'running' so the UI reflects active state
    await this.db.query(`UPDATE scans SET status='running' WHERE id=$1`, [scanId]);

    try {
      let rawResult: any = { vulnerabilities: [], summary: {} };

      if (scan.scan_types.includes('sast')) {
        this.logger.log(`Running Semgrep on ${scan.target_url}`);
        rawResult = await this.runSemgrep(scanId, scan.target_url);
      } else if (scan.scan_types.includes('container')) {
        this.logger.log(`Running Trivy on ${scan.target_url}`);
        rawResult = await this.runTrivy(scanId, scan.target_url);
      } else if (scan.scan_types.includes('api')) {
        this.logger.log(`Running API Scanner on ${scan.target_url}`);
        rawResult = await this.runApiScanner(scanId, scan.target_url);
      } else {
        const scanTypeMap: Record<string, string> = {
          'port_scan': 'ports',
          'ssl_analysis': 'ssl',
          // [FIX #14] 'http_headers' was missing — ContinuousMonitorService sends this
          // type and it was silently dropped (filtered out), resulting in no scan run.
          'http_headers': 'headers',
          'security_headers': 'headers',
          'sql_injection': 'sqli',
          'xss': 'xss',
          'dom_xss': 'dom-xss',
          'graphql': 'graphql',
          'ssrf': 'ssrf',
          'xxe': 'xxe',
          'csrf': 'csrf',
          'upload': 'upload',
          'cors_check': 'cors',
          'info_disclosure': 'info',
          'jwt_analysis': 'jwt',
          'open_redirect': 'redirect',
          'crawler': 'crawler',
          'dir_bruteforce': 'dir-bruteforce',
          'waf_detector': 'waf',
          'cloud_scanner': 'cloud',
          'api_fuzzer': 'api-fuzzer',
        };
        // [FIXED] Bug #3: Guard against empty rustScans.
        // If all selected scan_types are unknown/unmapped, rustScans will be an empty
        // string. Passing --scans "" to Clap causes a silent zero-result scan.
        // Instead, fail fast with a descriptive error.
        const rustScans = scan.scan_types
          .map((t: string) => scanTypeMap[t])
          .filter(Boolean)
          .join(',');

        if (!rustScans) {
          throw new Error(
            `No recognised scan types in request: [${scan.scan_types.join(', ')}]. ` +
            `Valid types: ${Object.keys(scanTypeMap).join(', ')}`,
          );
        }

        const args = [
          '--target', scan.target_url,
          '--scans', rustScans,
          '--json',
        ];
        rawResult = await this.runScannerProcess(scanId, args);
      }

      await this.resultQueue.add('scan_completed', {
        scanId,
        scan,
        rawResult,
      });

    } catch (err: any) {
      this.logger.error(`Scan ${scanId} failed: ${err.message}`);
      await this.resultQueue.add('scan_failed', {
        scanId,
        error: err.message,
      });
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
        const lines = d.toString().split('\n').filter(Boolean);
        for (const line of lines) {
          this.resultQueue.add('scan_progress', {
            scanId,
            message: line,
          }).catch(e => this.logger.error(e));
        }
      });

      proc.on('close', (code) => {
        if (code !== 0)
          return reject(new Error(`Scanner exited with code ${code}: ${stderr}`));
        try {
          resolve(JSON.parse(stdout));
        } catch {
          reject(new Error('Failed to parse scanner output'));
        }
      });

      proc.on('error', reject);
    });
  }

  // ── Specialized Scanners ──────────────────────────────────────
  private runSemgrep(scanId: string, target: string): Promise<any> {
    return new Promise((resolve) => {
      const proc = spawn('semgrep', ['scan', '--json', target]);
      let stdout = '';
      proc.stdout.on('data', (d) => { stdout += d.toString(); });
      proc.on('close', () => {
        try {
          const parsed = JSON.parse(stdout);
          const vulnerabilities = parsed.results.map((r: any) => ({
            title: r.check_id,
            description: r.extra.message,
            severity: r.extra.severity === 'ERROR' ? 'CRITICAL' : (r.extra.severity === 'WARNING' ? 'MEDIUM' : 'INFO'),
            cvss_score: r.extra.severity === 'ERROR' ? 9.0 : 5.0,
            affected_url: target,
            affected_parameter: r.path,
            evidence: [{ evidence_type: 'code_snippet', description: 'Line ' + r.start?.line }],
            category: 'SAST',
          }));
          resolve({ vulnerabilities, summary: { total_vulnerabilities: vulnerabilities.length } });
        } catch {
          this.logger.error(`Failed to parse semgrep output`);
          resolve({ vulnerabilities: [], summary: {} });
        }
      });
      proc.on('error', () => {
         this.logger.error(`Failed to spawn semgrep. Make sure it is installed.`);
         resolve({ vulnerabilities: [], summary: {} });
      });
    });
  }

  private runTrivy(scanId: string, target: string): Promise<any> {
    return new Promise((resolve) => {
      const proc = spawn('trivy', ['image', '-f', 'json', target]);
      let stdout = '';
      proc.stdout.on('data', (d) => { stdout += d.toString(); });
      proc.on('close', () => {
        try {
          const parsed = JSON.parse(stdout);
          const vulnerabilities: any[] = [];
          if (parsed.Results) {
            for (const res of parsed.Results) {
              if (res.Vulnerabilities) {
                for (const v of res.Vulnerabilities) {
                   vulnerabilities.push({
                      title: v.VulnerabilityID + ' in ' + v.PkgName,
                      description: v.Title || v.Description || 'No description provided',
                      severity: v.Severity === 'CRITICAL' ? 'CRITICAL' : v.Severity === 'HIGH' ? 'HIGH' : v.Severity === 'MEDIUM' ? 'MEDIUM' : 'LOW',
                      cvss_score: v.CVSS?.nvd?.V3Score || 5.0,
                      affected_url: target,
                      affected_parameter: v.PkgName,
                      cve_id: v.VulnerabilityID,
                      category: 'Container Security',
                   });
                }
              }
            }
          }
          resolve({ vulnerabilities, summary: { total_vulnerabilities: vulnerabilities.length } });
        } catch {
          this.logger.error(`Failed to parse trivy output`);
          resolve({ vulnerabilities: [], summary: {} });
        }
      });
      proc.on('error', () => {
         this.logger.error(`Failed to spawn trivy. Make sure it is installed.`);
         resolve({ vulnerabilities: [], summary: {} });
      });
    });
  }

  private async runApiScanner(scanId: string, targetUrl: string): Promise<any> {
     try {
       const api: any = await SwaggerParser.dereference(targetUrl);
       const vulnerabilities: any[] = [];
       
       if (!api.security || api.security.length === 0) {
         vulnerabilities.push({
           title: 'Missing Global Security Definitions',
           description: 'The OpenAPI specification does not define global security constraints.',
           severity: 'HIGH',
           cvss_score: 7.5,
           affected_url: targetUrl,
           category: 'API Security'
         });
       }

       return { vulnerabilities, summary: { total_vulnerabilities: vulnerabilities.length } };
     } catch (e: any) {
        this.logger.error(`API Scanner failed: ${e.message}`);
        return { vulnerabilities: [], summary: {} };
     }
  }
}
