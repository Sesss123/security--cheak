import { Module } from '@nestjs/common';
import { SmartWebService } from './smart-web.service';

@Module({
  providers: [SmartWebService],
  exports: [SmartWebService],
})
export class SmartWebModule {}
