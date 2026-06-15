import { Injectable, Logger } from '@nestjs/common';
import { QdrantClient } from '@qdrant/js-client-rest';
import { EmbeddingService } from './embedding.service';

@Injectable()
export class RetrievalService {
  private readonly logger = new Logger(RetrievalService.name);
  private qdrantClient: QdrantClient;
  private readonly COLLECTION_NAME = 'knowledge_base';

  constructor(private readonly embeddingService: EmbeddingService) {
    this.qdrantClient = new QdrantClient({
      url: process.env.QDRANT_URL ?? 'http://localhost:6333',
    });
  }

  async retrieveRelevantContext(query: string, limit: number = 5) {
    try {
      const vector = await this.embeddingService.getEmbedding(query);
      const searchResults = await this.qdrantClient.search(this.COLLECTION_NAME, {
        vector: vector,
        limit: limit,
        with_payload: true,
      });

      return searchResults.map(res => ({
        score: res.score,
        payload: res.payload,
      }));
    } catch (err) {
      this.logger.error('Failed to retrieve context from Vector DB', err);
      return [];
    }
  }
}
