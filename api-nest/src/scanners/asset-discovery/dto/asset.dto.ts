import { IsString, IsOptional, IsArray, IsInt } from 'class-validator';

export class AssetDiscoveryDto {
  @IsString()
  targetUrl: string;

  @IsOptional()
  @IsInt()
  maxDepth?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  modules?: string[]; // e.g., ['dns', 'ports', 'services', 'cloud', 'containers']
}

export interface DiscoveredAsset {
  id?: string;
  targetId: string;
  assetType: 'SUBDOMAIN' | 'IP' | 'PORT' | 'SERVICE' | 'API' | 'CLOUD_RESOURCE' | 'CONTAINER';
  value: string;
  metadata?: Record<string, any>;
  discoveredAt: Date;
}

export interface TechnologyAsset {
  id?: string;
  targetId: string;
  technology: string;
  version?: string;
  category: string;
  confidence: number;
}
