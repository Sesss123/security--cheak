import 'dotenv/config';
import { setGlobalDispatcher, Agent } from 'undici';

try {
  setGlobalDispatcher(new Agent({ keepAliveMaxTimeout: 10, keepAliveTimeout: 10 }));
} catch (e) {
  // Ignore
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
