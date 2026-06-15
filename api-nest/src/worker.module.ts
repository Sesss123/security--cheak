import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { ScannerWorker } from './workers/scanner.worker';

@Module({
  imports: [
    BullModule.forRoot({
      connection: {
        host: process.env.REDIS_HOST ?? 'localhost',
        port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
      },
    }),
    BullModule.registerQueue({
      name: 'scan-results',
    }),
  ],
  providers: [ScannerWorker],
})
export class WorkerModule {}
