import { Injectable, Logger } from '@nestjs/common';
import { QdrantClient } from '@qdrant/js-client-rest';
import axios from 'axios';
import { Vulnerability } from '../types';

/**
 * [FIX #6] RAG embeddings were previously random noise (Math.random()).
 *
 * Random vectors make cosine similarity meaningless — every "search" returns
 * arbitrary results, defeating the purpose of a RAG knowledge base.
 *
 * Fix: use the HuggingFace Inference API with the all-MiniLM-L6-v2 model
 * (384-dimensional sentence embeddings, free tier, no API key required for
 * the public model endpoint).
 *
 * Fallback: if the HuggingFace call fails (network error, rate limit, etc.),
 * we return a zero-vector rather than random noise. Zero-vectors produce a
 * similarity score of 0.0 for all candidates, which is an honest "unknown"
 * rather than a misleading random match.
 *
 * Optional: set HF_API_KEY env var to use the authenticated tier (higher
 * rate limits and priority queue).
 */
@Injectable()
export class RagService {
  private readonly logger = new Logger(RagService.name);
  private qdrantClient: QdrantClient;
  private readonly COLLECTION_NAME = 'vulnerabilities';
  private readonly EMBEDDING_DIM   = 384; // all-MiniLM-L6-v2 output size

  // HuggingFace Inference API endpoint for sentence embeddings
  private readonly HF_EMBEDDING_URL =
    'https://api-inference.huggingface.co/pipeline/feature-extraction/sentence-transformers/all-MiniLM-L6-v2';

  constructor() {
    this.qdrantClient = new QdrantClient({
      url: process.env.QDRANT_URL ?? 'http://localhost:6333',
      checkCompatibility: false,
    });
    this.initializeCollection().catch(e =>
      this.logger.error('Failed to init Qdrant collection', e),
    );
  }

  private async initializeCollection() {
    try {
      const collections = await this.qdrantClient.getCollections();
      const exists = collections.collections.some(c => c.name === this.COLLECTION_NAME);

      if (!exists) {
        await this.qdrantClient.createCollection(this.COLLECTION_NAME, {
          vectors: { size: this.EMBEDDING_DIM, distance: 'Cosine' },
        });
        this.logger.log(`Created Qdrant collection: ${this.COLLECTION_NAME}`);
      }
    } catch (err) {
      this.logger.error('Could not connect to Qdrant. Ensure it is running.', err);
    }
  }

  // ── Embedding Generation ────────────────────────────────────────────────

  /**
   * [FIX #6] Generates real 384-dimensional sentence embeddings via HuggingFace.
   *
   * On failure, returns a zero-vector (honest "I don't know") instead of
   * random noise (misleading fake similarity).
   */
  private async getEmbedding(text: string): Promise<number[]> {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      // Use API key if available (higher rate limits on free tier)
      if (process.env.HF_API_KEY) {
        headers['Authorization'] = `Bearer ${process.env.HF_API_KEY}`;
      }

      const response = await axios.post(
        this.HF_EMBEDDING_URL,
        { inputs: text },
        { headers, timeout: 15000 },
      );

      // HuggingFace returns: number[] for a single input
      const embedding = response.data as number[];

      if (!Array.isArray(embedding) || embedding.length !== this.EMBEDDING_DIM) {
        this.logger.warn(
          `HuggingFace returned unexpected embedding shape: ${JSON.stringify(embedding).slice(0, 80)}`,
        );
        return this.zeroVector();
      }

      return embedding;
    } catch (err: any) {
      // Graceful degradation — zero-vector is honest, random noise is not
      this.logger.warn(`HuggingFace embedding failed (${err.message}). Using zero-vector fallback.`);
      return this.zeroVector();
    }
  }

  /** Returns a 384-dimensional zero-vector (used as fallback). */
  private zeroVector(): number[] {
    return new Array(this.EMBEDDING_DIM).fill(0);
  }

  // ── Ingest ───────────────────────────────────────────────────────────────

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
            id: vuln.id,
            vector,
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

  // ── Search ────────────────────────────────────────────────────────────────

  /**
   * Searches for similar past vulnerabilities using vector similarity.
   */
  async searchSimilarVulnerabilities(query: string, limit: number = 3) {
    try {
      const vector = await this.getEmbedding(query);
      const searchResults = await this.qdrantClient.search(this.COLLECTION_NAME, {
        vector,
        limit,
        with_payload: true,
      });

      return searchResults.map(res => ({
        score:   res.score,
        payload: res.payload,
      }));
    } catch (err) {
      this.logger.error('Failed to search Vector DB', err);
      return [];
    }
  }
}
