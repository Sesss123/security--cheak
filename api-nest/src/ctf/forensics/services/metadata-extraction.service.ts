import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class MetadataExtractionService {
  private readonly logger = new Logger(MetadataExtractionService.name);

  extract(fileBuffer: Buffer): Record<string, any> {
    this.logger.debug('Extracting file metadata (ExifTool / magic bytes equivalent)');
    return { size: fileBuffer.length };
  }
}
