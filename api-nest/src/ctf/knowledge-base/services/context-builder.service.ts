import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class ContextBuilderService {
  private readonly logger = new Logger(ContextBuilderService.name);

  buildPrompt(contextBlocks: string[], query: string): string {
    this.logger.debug('Building LLM Context Prompt');
    return `Use the following context to answer:\n\n${contextBlocks.join('\n')}\n\nQuery: ${query}`;
  }
}
