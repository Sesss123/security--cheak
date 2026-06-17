import { Injectable, Logger, Inject } from '@nestjs/common';
import { ScannerService } from '../../services/scanner.service';

@Injectable()
export class SmartWebService {
  private readonly logger = new Logger(SmartWebService.name);

  constructor(
    private readonly scannerService: ScannerService,
  ) {}

  async triggerSmartScan(targetId: string, targetUrl: string, framework: string): Promise<void> {
    this.logger.log(`Triggering Smart Web Scan for target ${targetId}: ${targetUrl} [Framework: ${framework}]`);
    
    // Delegate to the Rust scanner
    await this.scannerService.startScan({
      target_url: targetUrl,
      modules: ['smart_scan'],
      mode: 'smart_web',
      options: {
        framework, // Passes framework down so Rust scanner can use specific profile
      }
    } as any, targetId);
  }
}
