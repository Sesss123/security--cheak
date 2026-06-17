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
import { AppModule } from './app.module';
import { WsAdapter } from '@nestjs/platform-ws';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';

async function bootstrap() {
  if (!process.env.JWT_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET environment variable is missing.');
    process.exit(1);
  }

  const app = await NestFactory.create(AppModule, { bodyParser: false });
  // [MEDIUM] JSON Limit
  const express = require('express');
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));

  // [MEDIUM] CORS Policy
  if (process.env.NODE_ENV === 'production' && !process.env.ALLOWED_ORIGINS) {
    console.error('FATAL ERROR: ALLOWED_ORIGINS must be set in production.');
    process.exit(1);
  }
  app.enableCors({ origin: process.env.ALLOWED_ORIGINS?.split(',') ?? ['http://localhost:5173'] });
  app.useWebSocketAdapter(new WsAdapter(app));

  await app.listen(process.env.PORT ?? 3001);
}
bootstrap();
