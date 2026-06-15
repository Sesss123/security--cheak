import { Injectable, Logger } from '@nestjs/common';
import { QdrantClient } from '@qdrant/js-client-rest';
import { Vulnerability } from '../types';

@Injectable()
export class RagService {
  private readonly logger = new Logger(RagService.name);
  private qdrantClient: QdrantClient;
  private readonly COLLECTION_NAME = 'vulnerabilities';

  constructor() {
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
          vectors: { size: 384, distance: 'Cosine' }, // Assuming 384 dim (e.g., all-MiniLM-L6-v2)
        });
        this.logger.log(`Created Qdrant collection: ${this.COLLECTION_NAME}`);
      }
    } catch (err) {
      this.logger.error('Could not connect to Qdrant. Ensure it is running.', err);
    }
  }

  /**
   * Generates vector embeddings for a given text.
   * Currently uses a mock array for demonstration unless an API is configured.
   */
  private async getEmbedding(text: string): Promise<number[]> {
    // In a production environment, you would call OpenAI, HuggingFace, etc.
    // Example: fetch('https://api-inference.huggingface.co/pipeline/feature-extraction/sentence-transformers/all-MiniLM-L6-v2', ...)
    
    // For now, return a mock 384-dimensional vector
    return Array.from({ length: 384 }, () => Math.random() * 2 - 1);
  }

  /**
   * Embeds a new vulnerability and stores it in Qdrant for future RAG queries.
   */
  async ingestVulnerability(vuln: Vulnerability) {
    const textToEmbed = `
      Title: ${vuln.title}
      Severity: ${vuln.severity}
      Category: ${vuln.category}
      Description: ${vuln.description}
      Remediation: ${vuln.remediation ?? ''}
      AI Fix: ${vuln.ai_remediation_steps ? JSON.stringify(vuln.ai_remediation_steps) : ''}
    `.trim();

    try {
      const vector = await this.getEmbedding(textToEmbed);
      
      await this.qdrantClient.upsert(this.COLLECTION_NAME, {
        wait: true,
        points: [
          {
            id: vuln.id, // Must be UUID compatible
            vector: vector,
            payload: {
              title: vuln.title,
              severity: vuln.severity,
              target_url: vuln.affected_url,
              remediation: vuln.remediation,
              ai_fix: vuln.ai_remediation_steps,
            },
          },
        ],
      });
      this.logger.log(`Ingested vulnerability ${vuln.id} into Vector DB`);
    } catch (err) {
      this.logger.error(`Failed to ingest vulnerability ${vuln.id}`, err);
    }
  }

  /**
   * Searches for similar past vulnerabilities.
   */
  async searchSimilarVulnerabilities(query: string, limit: number = 3) {
    try {
      const vector = await this.getEmbedding(query);
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
      this.logger.error('Failed to search Vector DB', err);
      return [];
    }
  }
}
