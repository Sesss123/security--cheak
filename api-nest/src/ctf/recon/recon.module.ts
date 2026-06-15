import { Module } from '@nestjs/common';
import { SubdomainDiscoveryService } from './services/subdomain-discovery.service';
import { DnsEnumerationService } from './services/dns-enumeration.service';
import { TechnologyFingerprintService } from './services/technology-fingerprint.service';
import { HeaderAnalysisService } from './services/header-analysis.service';
import { JavascriptAnalysisService } from './services/javascript-analysis.service';
import { EndpointDiscoveryService } from './services/endpoint-discovery.service';
import { AttackSurfaceMapper } from './services/attack-surface-mapper';
import { ReconReportGenerator } from './services/recon-report.generator';

@Module({
  providers: [
    SubdomainDiscoveryService,
    DnsEnumerationService,
    TechnologyFingerprintService,
    HeaderAnalysisService,
    JavascriptAnalysisService,
    EndpointDiscoveryService,
    AttackSurfaceMapper,
    ReconReportGenerator,
  ],
  exports: [ReconReportGenerator, SubdomainDiscoveryService],
})
export class ReconModule {}
