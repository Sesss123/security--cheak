import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import axios from 'axios';
import { Vulnerability } from '../types';

@Injectable()
export class ThreatIntelService implements OnModuleInit {
  private readonly logger = new Logger(ThreatIntelService.name);

  // APIs
  private readonly NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly EPSS_BASE_URL = 'https://api.first.org/data/v1/epss';
  private readonly CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

  // Caches
  private cisaKevMap: Set<string> = new Set();
  private nvdCache: Map<string, any> = new Map();
  private epssCache: Map<string, number> = new Map();

  async onModuleInit() {
    await this.loadCisaKevData();
  }

  private async loadCisaKevData() {
    try {
      this.logger.log('Loading CISA KEV catalog...');
      const response = await axios.get(this.CISA_KEV_URL, { timeout: 10000 });
      if (response.data && response.data.vulnerabilities) {
        response.data.vulnerabilities.forEach((v: any) => {
          this.cisaKevMap.add(v.cveID);
        });
        this.logger.log(`Loaded ${this.cisaKevMap.size} CVEs from CISA KEV catalog.`);
      }
    } catch (err: any) {
      this.logger.warn(`Failed to load CISA KEV data: ${err.message}`);
    }
  }

  private async getEpssScore(cveId: string): Promise<number> {
    if (this.epssCache.has(cveId)) {
      return this.epssCache.get(cveId)!;
    }
    try {
      const response = await axios.get(`${this.EPSS_BASE_URL}?cve=${cveId}`, { timeout: 5000 });
      if (response.data && response.data.data && response.data.data.length > 0) {
        const score = parseFloat(response.data.data[0].epss);
        this.epssCache.set(cveId, score);
        return score;
      }
    } catch (err: any) {
      this.logger.debug(`Failed to fetch EPSS for ${cveId}: ${err.message}`);
    }
    return 0;
  }

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
      const keyword = encodeURIComponent(vuln.title.substring(0, 50));
      
      let cveData: any = null;
      if (this.nvdCache.has(keyword)) {
        cveData = this.nvdCache.get(keyword);
      } else {
        const nvdUrl = `${this.NVD_BASE_URL}?keywordSearch=${keyword}&resultsPerPage=1`;
        const response = await axios.get(nvdUrl, {
          headers: process.env.NVD_API_KEY ? { 'apiKey': process.env.NVD_API_KEY } : {},
          timeout: 5000,
        });
        
        if (response.data && response.data.vulnerabilities && response.data.vulnerabilities.length > 0) {
          cveData = response.data.vulnerabilities[0].cve;
          this.nvdCache.set(keyword, cveData);
        }
      }

      if (cveData) {
        cve_id = cveData.id;
        const baseSeverity = cveData.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? threat_score;
        threat_score = baseSeverity;
        
        // 1. Check CISA KEV (Actively exploited)
        if (cve_id && this.cisaKevMap.has(cve_id)) {
            exploit_available = true;
            threat_score = Math.min(threat_score * 1.2, 10.0); // Boost +20%
        }

        // 2. Check EPSS (Probability of exploitation)
        if (cve_id) {
            const epssScore = await this.getEpssScore(cve_id);
            if (epssScore > 0.5) { // High probability of exploitation
                exploit_available = true;
                threat_score += (epssScore * 2); // Boost based on probability
            }
        }
      } else {
        // Fallback heuristics if API fails or no CVE found
        if (vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH') {
           exploit_available = vuln.title.toLowerCase().includes('rce') || vuln.title.toLowerCase().includes('sql');
           threat_score = exploit_available ? threat_score + 1.0 : threat_score;
        }
      }
    } catch (err: any) {
      this.logger.warn(`Failed to fetch Threat Intel for ${vuln.title}: ${err.message}`);
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
