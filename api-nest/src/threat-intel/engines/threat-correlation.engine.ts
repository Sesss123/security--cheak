import { Injectable, Logger } from '@nestjs/common';
import { Vulnerability } from '../../types';
import { EnrichmentData } from '../dtos/enrichment.dto';

@Injectable()
export class ThreatCorrelationEngine {
  private readonly logger = new Logger(ThreatCorrelationEngine.name);

  correlate(vuln: Vulnerability, isCisaKev: boolean, exploitAvailable: boolean, cvssScore?: number): EnrichmentData {
    let threatScore = vuln.cvss_score;
    if (cvssScore && cvssScore > threatScore) {
      threatScore = cvssScore;
    }

    const summaryParts: string[] = [];

    if (isCisaKev) {
      threatScore = Math.max(threatScore, 9.5); // Elevate to critical
      summaryParts.push('This vulnerability class is known to be actively exploited in the wild (CISA KEV).');
    }

    if (exploitAvailable) {
      threatScore = Math.max(threatScore, 7.5); // Elevate to high at minimum
      summaryParts.push('Public exploit proof-of-concept is available.');
    }

    return {
      cveId: vuln.cve_id,
      isCisaKev,
      exploitAvailable,
      cvssScore: cvssScore || vuln.cvss_score,
      threatScore,
      threatSummary: summaryParts.join(' ') || 'Standard vulnerability profile.',
    };
  }
}
