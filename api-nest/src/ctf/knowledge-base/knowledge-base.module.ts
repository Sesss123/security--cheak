import { Module } from '@nestjs/common';
import { EmbeddingService } from './services/embedding.service';
import { RetrievalService } from './services/retrieval.service';
import { KnowledgeIndexerService } from './services/knowledge-indexer.service';
import { ContextBuilderService } from './services/context-builder.service';
import { QdrantIntegrationService } from './services/qdrant-integration.service';
import { RagAnalysisService } from './services/rag-analysis.service';

@Module({
  providers: [
    EmbeddingService,
    RetrievalService,
    KnowledgeIndexerService,
    ContextBuilderService,
    QdrantIntegrationService,
    RagAnalysisService,
  ],
  exports: [RagAnalysisService, KnowledgeIndexerService],
})
export class KnowledgeBaseModule {}
