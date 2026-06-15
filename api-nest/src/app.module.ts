import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { BullModule } from '@nestjs/bullmq';
import { ScheduleModule } from '@nestjs/schedule';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DatabaseModule } from './db/database.module';
import { AiService } from './services/ai.service';
import { ScannerService } from './services/scanner.service';
import { RagService } from './services/rag.service';
import { ThreatIntelService } from './services/threat-intel.service';
import { AlertService } from './services/alert.service';
import { MonitoringService } from './services/monitoring.service';
import { ScanGateway } from './gateways/scan.gateway';
import { AuthController } from './controllers/auth.controller';
import { ScanController } from './controllers/scan.controller';
import { AnalyticsController } from './controllers/analytics.controller';
import { ResultAggregatorProcessor } from './workers/result-aggregator.processor.js';
import { CtfModule } from './ctf/ctf.module';
import { ApiScannerModule } from './scanners/api-scanner/api-scanner.module';
import { ContainerScannerModule } from './scanners/container-scanner/container-scanner.module';
import { CloudScannerModule } from './scanners/cloud-scanner/cloud-scanner.module';
import { RagModule } from './ai/rag/rag.module';

@Module({
  imports: [
    DatabaseModule,
    ApiScannerModule,
    ContainerScannerModule,
    CloudScannerModule,
    CtfModule,
    RagModule,
    ScheduleModule.forRoot(),
    BullModule.forRoot({
      connection: {
        host: process.env.REDIS_HOST ?? 'localhost',
        port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
      },
    }),
    BullModule.registerQueue({
      name: 'scan-jobs',
    }),
    BullModule.registerQueue({
      name: 'scan-results',
    }),
  ],
  controllers: [
    AppController,
    AuthController,
    ScanController,
    AnalyticsController,
  ],
  providers: [
    AppService, 
    AiService, 
    ScannerService, 
    RagService, 
    ThreatIntelService, 
    AlertService,
    MonitoringService,
    ScanGateway,
    ResultAggregatorProcessor
  ],
})
export class AppModule {}
