import { Processor, WorkerHost, InjectQueue } from '@nestjs/bullmq';
import { Job, Queue } from 'bullmq';
import { Logger } from '@nestjs/common';
import { spawn } from 'child_process';
import SwaggerParser from '@apidevtools/swagger-parser';
import { Scan } from '../types';

@Processor('scan-jobs')
export class ScannerWorker extends WorkerHost {
  private readonly logger = new Logger(ScannerWorker.name);
  private readonly SCANNER_BIN = process.env.SCANNER_BIN ?? (process.env.NODE_ENV === 'production' ? '/scanner/scanner' : '../scanner/target/release/scanner.exe');

  constructor(
    @InjectQueue('scan-results') private resultQueue: Queue,
  ) {
    super();
  }

  async process(job: Job<{ scanId: string; scan: Scan }, any, string>): Promise<any> {
    const { scanId, scan } = job.data;
    this.logger.log(`Worker processing scan job for ID: ${scanId}`);

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
        const args = [
          '--target', scan.target_url,
          '--scans', scan.scan_types.join(','),
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
