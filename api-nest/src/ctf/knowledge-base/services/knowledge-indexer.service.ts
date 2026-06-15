import { Injectable, Logger } from '@nestjs/common';
import { EmbeddingService } from './embedding.service';
import { QdrantIntegrationService } from './qdrant-integration.service';

@Injectable()
export class KnowledgeIndexerService {
  private readonly logger = new Logger(KnowledgeIndexerService.name);

  constructor(
    private readonly embeddingSvc: EmbeddingService,
    private readonly qdrant: QdrantIntegrationService,
  ) {}

  async indexDocument(id: string, content: string): Promise<void> {
    this.logger.debug(`Indexing CTF document ${id}`);
    const vector = await this.embeddingSvc.generateEmbeddings(content);
    await this.qdrant.upsert(id, vector, { content });
  }
}
