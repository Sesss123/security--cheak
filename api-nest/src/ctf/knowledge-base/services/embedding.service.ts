import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class EmbeddingService {
  private readonly logger = new Logger(EmbeddingService.name);

  async generateEmbeddings(text: string): Promise<number[]> {
    this.logger.debug('Generating embeddings for CTF knowledge');
    // Mock embedding generation
    return [0.1, 0.2, 0.3];
  }
}
