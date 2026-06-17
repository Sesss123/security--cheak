import { Injectable, Logger } from '@nestjs/common';
import { ScannerService } from '../../services/scanner.service';
import { Scan } from '../../types';

@Injectable()
export class SmartWebService {
  private readonly logger = new Logger(SmartWebService.name);

  constructor(
    private readonly scannerService: ScannerService,
  ) {}

  async triggerSmartScan(userId: string, targetUrl: string, framework: string): Promise<Scan> {
    this.logger.log(`Triggering Smart Web Scan for user ${userId}: ${targetUrl} [Framework: ${framework}]`);
    
    // Delegate to the Rust scanner
    return await this.scannerService.startScan({
      target_url: targetUrl,
      modules: ['smart_scan'],
      mode: 'smart_web',
      options: {
        framework, // Passes framework down so Rust scanner can use specific profile
      }
    } as any, userId);
  }
}
