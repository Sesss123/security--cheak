import { Injectable, Logger } from '@nestjs/common';
import { RagContext } from '../dtos/rag.dto';
import { RetrievalService } from './retrieval.service';

@Injectable()
export class RagAnalysisService {
  private readonly logger = new Logger(RagAnalysisService.name);

  constructor(private readonly retrieval: RetrievalService) {}

  async analyze(query: string): Promise<RagContext> {
    this.logger.debug(`Executing RAG analysis for query: ${query}`);
    const results = await this.retrieval.retrieve(query);
    
    return {
      relevantWriteups: results.filter(r => r.includes('writeup')),
      similarChallenges: results.filter(r => r.includes('challenge')),
      suggestedConcepts: ['Review injection payloads', 'Understand modern WAF rules'],
      learningGuidance: 'Based on the context, focus on advanced SQLi evasion techniques.',
    };
  }
}
