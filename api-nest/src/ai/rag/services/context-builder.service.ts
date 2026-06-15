import { Injectable } from '@nestjs/common';
import { RetrievalService } from './retrieval.service';
import { Vulnerability } from '../../../types';

@Injectable()
export class ContextBuilderService {
  constructor(private readonly retrievalService: RetrievalService) {}

  async buildVulnAnalysisContext(vuln: Vulnerability): Promise<string> {
    const query = `${vuln.title} ${vuln.category} ${vuln.description}`;
    const similarDocs = await this.retrievalService.retrieveRelevantContext(query, 3);
    
    let context = '';
    if (similarDocs.length > 0) {
      context += `\n\n--- KNOWLEDGE BASE CONTEXT ---\n`;
      context += similarDocs.map((doc, idx) => `[${idx+1}] Source: ${doc.payload?.source}\nTitle: ${doc.payload?.title}\nContent: ${doc.payload?.content}`).join('\n\n');
    }
    return context;
  }

  async buildChatContext(userMessage: string): Promise<string> {
    const similarDocs = await this.retrievalService.retrieveRelevantContext(userMessage, 5);
    
    let context = '';
    if (similarDocs.length > 0) {
      context += `\n\n--- ENTERPRISE KNOWLEDGE BASE ---\n`;
      context += similarDocs.map((doc, idx) => `[${idx+1}] Source: ${doc.payload?.source}\nTitle: ${doc.payload?.title}\nContent: ${doc.payload?.content}`).join('\n\n');
    }
    return context;
  }
}
