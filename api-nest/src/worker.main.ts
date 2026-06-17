import 'dotenv/config';

// Patch global fetch to resolve undici version mismatch issues with QdrantClient
const originalFetch = globalThis.fetch;
if (originalFetch) {
  globalThis.fetch = function (input: any, init: any) {
    if (init && init.dispatcher) {
      delete init.dispatcher;
    }
    return originalFetch(input, init);
  };
}
import { NestFactory } from '@nestjs/core';
import { WorkerModule } from './worker.module';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.createApplicationContext(WorkerModule);
  app.enableShutdownHooks();
  Logger.log('Worker node is running and waiting for scan jobs...', 'WorkerMain');
}
bootstrap();
