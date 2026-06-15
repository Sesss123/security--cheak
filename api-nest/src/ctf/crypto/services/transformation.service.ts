import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class TransformationService {
  private readonly logger = new Logger(TransformationService.name);

  transform(input: string, transformation: string): string {
    this.logger.debug(`Applying transformation: ${transformation}`);
    if (transformation === 'base64_decode') {
      return Buffer.from(input, 'base64').toString();
    }
    if (transformation === 'hex_decode') {
      return Buffer.from(input, 'hex').toString();
    }
    return input;
  }
}
