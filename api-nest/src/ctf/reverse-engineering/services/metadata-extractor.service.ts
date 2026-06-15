import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class MetadataExtractorService {
  private readonly logger = new Logger(MetadataExtractorService.name);

  extract(buffer: Buffer): Record<string, string> {
    this.logger.debug('Extracting binary metadata');
    return { compiler: 'GCC', compilationTime: 'Unknown' };
  }
}
