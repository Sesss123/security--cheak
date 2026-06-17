import { Module } from '@nestjs/common';
import { ReconService } from './recon.service';

@Module({
  providers: [ReconService],
  exports: [ReconService],
})
export class ReconModule {}
