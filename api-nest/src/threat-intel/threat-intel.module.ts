import { Module } from '@nestjs/common';
import { CveService } from './services/cve.service';
import { CisaService } from './services/cisa.service';
import { ExploitIntelService } from './services/exploit-intel.service';
import { ThreatIntelService } from './services/threat-intel.service';
import { ThreatCorrelationEngine } from './engines/threat-correlation.engine';

@Module({
  providers: [
    CveService,
    CisaService,
    ExploitIntelService,
    ThreatCorrelationEngine,
    ThreatIntelService,
  ],
  exports: [
    ThreatIntelService,
  ],
})
export class ThreatIntelModule {}
