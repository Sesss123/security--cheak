import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class IocExtractionService {
  private readonly logger = new Logger(IocExtractionService.name);

  extract(fileContent: string): string[] {
    this.logger.debug('Extracting Indicators of Compromise (IPs, URLs, Hashes)');
    const iocs: string[] = [];
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    const matches = fileContent.match(ipRegex);
    if (matches) {
      iocs.push(...matches);
    }
    return [...new Set(iocs)];
  }
}
