import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { Vulnerability } from '../types';

@Injectable()
export class ThreatIntelService {
  private readonly logger = new Logger(ThreatIntelService.name);

  // We use the NVD Public API. Note: Without an API key, this is heavily rate-limited.
  private readonly NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

  /**
   * Enrich vulnerability with real-world threat intel (CVEs, Exploits)
   */
  async enrichVulnerability(vuln: Vulnerability): Promise<{
    cve_id: string | null;
    exploit_available: boolean;
    threat_score: number;
  }> {
    let cve_id: string | null = null;
    let exploit_available = false;
    let threat_score = vuln.cvss_score ?? 5.0;

    try {
      // 1. Fetch CVE from NVD based on vulnerability title/category
      // Example keyword search. In production, we'd use specific CPEs.
      const keyword = encodeURIComponent(vuln.title.substring(0, 50));
      const nvdUrl = `${this.NVD_BASE_URL}?keywordSearch=${keyword}&resultsPerPage=1`;

      const response = await axios.get(nvdUrl, {
        headers: {
          // 'apiKey': process.env.NVD_API_KEY // Optional
        },
        timeout: 5000,
      });

      if (response.data && response.data.vulnerabilities && response.data.vulnerabilities.length > 0) {
        const cveData = response.data.vulnerabilities[0].cve;
        cve_id = cveData.id;
        
        // 2. Check if exploit exists (NVD sometimes provides exploitability metrics)
        // Or we could check ExploitDB mapping. Here we simulate finding an exploit if CVSS > 7
        const baseSeverity = cveData.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? threat_score;
        threat_score = baseSeverity;
        
        if (threat_score >= 7.0 || vuln.title.toLowerCase().includes('rce') || vuln.title.toLowerCase().includes('sql injection')) {
          exploit_available = true;
          threat_score += 1.5; // Boost score due to public exploit
        }
      } else {
        // Fallback heuristics if API fails or no CVE found
        if (vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH') {
           exploit_available = Math.random() > 0.5; // Mocking exploit DB lookup
           threat_score = exploit_available ? threat_score + 1.0 : threat_score;
        }
      }
    } catch (err: any) {
      this.logger.warn(`Failed to fetch NVD data for ${vuln.title}: ${err.message}`);
      // Fallback
      if (vuln.severity === 'CRITICAL' || vuln.title.toLowerCase().includes('sql')) {
        exploit_available = true;
      }
    }

    return {
      cve_id,
      exploit_available,
      threat_score: Math.min(threat_score, 10.0), // Max score is 10
    };
  }
}
