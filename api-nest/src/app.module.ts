import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DatabaseModule } from './db/database.module';
import { AiService } from './services/ai.service';
import { ScannerService } from './services/scanner.service';
import { RagService } from './services/rag.service';
import { ThreatIntelService } from './services/threat-intel.service';
import { ScanGateway } from './gateways/scan.gateway';
import { AuthController } from './controllers/auth.controller';
import { ScanController } from './controllers/scan.controller';
import { AnalyticsController } from './controllers/analytics.controller';
import { ScannerWorker } from './workers/scanner.worker';

@Module({
  imports: [
    DatabaseModule,
    ClientsModule.register([
      {
        name: 'SCANNER_SERVICE',
        transport: Transport.RMQ,
        options: {
          urls: [process.env.RABBITMQ_URL ?? 'amqp://user:password@localhost:5672'],
          queue: 'scan_queue',
          queueOptions: {
            durable: true,
          },
        },
      },
    ]),
  ],
  controllers: [
    AppController,
    AuthController,
    ScanController,
    AnalyticsController,
    ScannerWorker,
  ],
  providers: [AppService, AiService, ScannerService, RagService, ThreatIntelService, ScanGateway],
})
export class AppModule {}
