import { Injectable, Logger } from '@nestjs/common';
import { EmbeddingService } from './embedding.service';
import { QdrantIntegrationService } from './qdrant-integration.service';

@Injectable()
export class RetrievalService {
  private readonly logger = new Logger(RetrievalService.name);

  constructor(
    private readonly embeddingSvc: EmbeddingService,
    private readonly qdrant: QdrantIntegrationService,
  ) {}

  async retrieve(query: string): Promise<string[]> {
    this.logger.debug(`Retrieving context for query: ${query}`);
    const vector = await this.embeddingSvc.generateEmbeddings(query);
    return this.qdrant.search(vector);
  }
}
