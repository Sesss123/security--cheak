import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { ScheduleModule } from '@nestjs/schedule';

import { ScannerWorker } from './workers/scanner.worker';
import { ResultAggregatorProcessor } from './workers/result-aggregator.processor';

// DatabaseModule is @Global() so DB_POOL token is available to all providers below
import { DatabaseModule } from './db/database.module';
import { AiService } from './services/ai.service';
import { RagService } from './services/rag.service';
import { ThreatIntelService } from './services/threat-intel.service';
import { AlertService } from './services/alert.service';
import { ScanGateway } from './gateways/scan.gateway';
import { RagModule } from './ai/rag/rag.module';

/**
 * WorkerModule — runs inside the dedicated worker container (npm run start:worker).
 *
 * This module owns:
 *   - ScannerWorker      : consumes 'scan-jobs' queue, spawns Rust binary
 *   - ResultAggregatorProcessor : consumes 'scan-results' queue, persists to DB & broadcasts WS
 *
 * NOTE: ScanGateway is injected so ResultAggregatorProcessor can call broadcast().
 * In the worker context (NestFactory.createApplicationContext) there is no WS server,
 * so the rooms Map is always empty and broadcasts are no-ops. Real-time updates are
 * forwarded only from the API container which has active WebSocket connections.
 * A Redis pub/sub bridge can be added later to propagate events across processes.
 */
@Module({
  imports: [
    // Provides DB_POOL token globally within this module context
    DatabaseModule,
    RagModule,

    // ScheduleModule is required by the @nestjs/schedule decorators used transitively
    ScheduleModule.forRoot(),

    // BullMQ connection shared by both workers
    BullModule.forRoot({
      connection: {
        host: process.env.REDIS_HOST ?? 'localhost',
        port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
      },
    }),

    // Register both queues — ScannerWorker produces scan-results, ResultAggregatorProcessor consumes it
    BullModule.registerQueue(
      { name: 'scan-jobs' },
      { name: 'scan-results' },
    ),
  ],
  providers: [
    // Queue consumers
    ScannerWorker,
    ResultAggregatorProcessor,

    // Dependencies of ResultAggregatorProcessor
    AiService,
    RagService,
    ThreatIntelService,
    AlertService,
    ScanGateway,
  ],
})
export class WorkerModule {}
