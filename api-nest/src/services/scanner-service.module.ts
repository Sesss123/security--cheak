import { Module, Global } from '@nestjs/common';
import { ScannerService } from './scanner.service';
import { ScanGateway } from '../gateways/scan.gateway';
import { BullModule } from '@nestjs/bullmq';

@Global()
@Module({
  imports: [
    BullModule.registerQueue({
      name: 'scan-jobs',
    }),
  ],
  providers: [ScannerService, ScanGateway],
  exports: [ScannerService, ScanGateway, BullModule],
})
export class ScannerServiceModule {}
