import { Module } from '@nestjs/common';
import { AssetDiscoveryService } from './asset-discovery.service';

@Module({
  providers: [AssetDiscoveryService],
  exports: [AssetDiscoveryService],
})
export class AssetDiscoveryModule {}
