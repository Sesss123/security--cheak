import { Injectable, Logger } from '@nestjs/common';
import { QdrantClient } from '@qdrant/js-client-rest';
import { EmbeddingService } from './embedding.service';
import { Vulnerability } from '../../../types';

export interface KnowledgeDocument {
  id: string;
  title: string;
  content: string;
  source: 'OWASP' | 'CWE' | 'CAPEC' | 'INTERNAL' | 'VULNERABILITY';
  metadata?: Record<string, any>;
}

@Injectable()
export class KnowledgeService {
  private readonly logger = new Logger(KnowledgeService.name);
  private qdrantClient: QdrantClient;
  private readonly COLLECTION_NAME = 'knowledge_base';

  constructor(private readonly embeddingService: EmbeddingService) {
    this.qdrantClient = new QdrantClient({
      url: process.env.QDRANT_URL ?? 'http://localhost:6333',
    });
    this.initializeCollection().catch(e => this.logger.error('Failed to init Qdrant', e));
  }

  private async initializeCollection() {
    try {
      const collections = await this.qdrantClient.getCollections();
      const exists = collections.collections.some(c => c.name === this.COLLECTION_NAME);

      if (!exists) {
        await this.qdrantClient.createCollection(this.COLLECTION_NAME, {
          vectors: { size: 384, distance: 'Cosine' },
        });
        this.logger.log(`Created Qdrant collection: ${this.COLLECTION_NAME}`);
      }
    } catch (err) {
      this.logger.error('Could not connect to Qdrant. Ensure it is running.', err);
    }
  }

  async ingestDocument(doc: KnowledgeDocument) {
    const textToEmbed = `Title: ${doc.title}\nSource: ${doc.source}\nContent: ${doc.content}`;

    try {
      const vector = await this.embeddingService.getEmbedding(textToEmbed);
      
      await this.qdrantClient.upsert(this.COLLECTION_NAME, {
        wait: true,
        points: [
          {
            id: doc.id,
            vector: vector,
            payload: {
              title: doc.title,
              source: doc.source,
              content: doc.content,
              ...doc.metadata,
            },
          },
        ],
      });
      this.logger.log(`Ingested knowledge document ${doc.id}`);
    } catch (err) {
      this.logger.error(`Failed to ingest document ${doc.id}`, err);
    }
  }

  async ingestVulnerability(vuln: Vulnerability) {
    const doc: KnowledgeDocument = {
      id: vuln.id,
      title: vuln.title,
      content: `Description: ${vuln.description}\nSeverity: ${vuln.severity}\nCategory: ${vuln.category}\nRemediation: ${vuln.remediation ?? ''}`,
      source: 'VULNERABILITY',
      metadata: {
        severity: vuln.severity,
        target_url: vuln.affected_url,
        ai_fix: vuln.ai_remediation_steps,
      }
    };
    await this.ingestDocument(doc);
  }
}
