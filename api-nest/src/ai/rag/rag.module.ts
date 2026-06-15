import { Module } from '@nestjs/common';
import { EmbeddingService } from './services/embedding.service';
import { KnowledgeService } from './services/knowledge.service';
import { RetrievalService } from './services/retrieval.service';
import { ContextBuilderService } from './services/context-builder.service';

@Module({
  providers: [
    EmbeddingService,
    KnowledgeService,
    RetrievalService,
    ContextBuilderService,
  ],
  exports: [
    RetrievalService,
    ContextBuilderService,
  ],
})
export class RagModule {}
