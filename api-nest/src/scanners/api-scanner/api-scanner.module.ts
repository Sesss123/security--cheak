import { Module } from '@nestjs/common';
import { OpenApiParserService } from './services/openapi-parser.service';
import { EndpointDiscoveryService } from './services/endpoint-discovery.service';
import { JwtAnalyzerService } from './services/jwt-analyzer.service';
import { AuthorizationAnalyzerService } from './services/authorization-analyzer.service';
import { IdorDetectionService } from './services/idor-detection.service';
import { RateLimitAnalyzerService } from './services/rate-limit-analyzer.service';
import { ApiRiskScoringService } from './services/api-risk-scoring.service';

@Module({
  providers: [
    OpenApiParserService,
    EndpointDiscoveryService,
    JwtAnalyzerService,
    AuthorizationAnalyzerService,
    IdorDetectionService,
    RateLimitAnalyzerService,
    ApiRiskScoringService,
  ],
  exports: [
    OpenApiParserService,
    EndpointDiscoveryService,
    JwtAnalyzerService,
    AuthorizationAnalyzerService,
    IdorDetectionService,
    RateLimitAnalyzerService,
    ApiRiskScoringService,
  ],
})
export class ApiScannerModule {}
