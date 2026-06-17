import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import axios from 'axios';
import { Vulnerability } from '../types';

/**
 * [FIX #11] NVD API is now rate-limited.
 *   Without NVD_API_KEY: max 5 req/30s — we throttle to 1 req/6s.
 *   With NVD_API_KEY:    max 50 req/30s — we throttle to 1 req/650ms.
 *
 * [FIX #19] EPSS score accumulation was not clamped mid-calculation,
 *   allowing threat_score to exceed 10.0 before the final Math.min().
 *   Each intermediate boost is now individually clamped.
 *
 * [FIX #28] nvdCache and epssCache Maps grew unbounded (OOM risk on
 *   long-running containers). Added MAX_CACHE_SIZE cap with LRU-style
 *   eviction of the oldest 20% when the limit is reached.
 */
@Injectable()
export class ThreatIntelService implements OnModuleInit {
  private readonly logger = new Logger(ThreatIntelService.name);

  // External API endpoints
  private readonly NVD_BASE_URL  = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly EPSS_BASE_URL = 'https://api.first.org/data/v1/epss';
  private readonly CISA_KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

  // [FIX #28] Cache size guard — prevents unbounded memory growth
  private readonly MAX_CACHE_SIZE = 1000;

  // In-memory caches
  private cisaKevMap: Set<string>    = new Set();
  private nvdCache:  Map<string, any> = new Map();
  private epssCache: Map<string, number> = new Map();

  // [FIX #11] Rate-limit state: track timestamp of last NVD request
  private lastNvdRequestTime = 0;
  // Unauthenticated: 5 req/30s — use conservative 6-second gap
  // Authenticated:  50 req/30s — 650ms gap is safe
  private readonly NVD_MIN_INTERVAL_MS = process.env.NVD_API_KEY ? 650 : 6000;

  async onModuleInit() {
    await this.loadCisaKevData();
  }

  // ── CISA KEV ─────────────────────────────────────────────────────────────

  private async loadCisaKevData() {
    try {
      this.logger.log('Loading CISA KEV catalog...');
      const response = await axios.get(this.CISA_KEV_URL, { timeout: 10000 });
      if (response.data?.vulnerabilities) {
        for (const v of response.data.vulnerabilities) {
          this.cisaKevMap.add(v.cveID);
        }
        this.logger.log(`Loaded ${this.cisaKevMap.size} CVEs from CISA KEV catalog.`);
      }
    } catch (err: any) {
      this.logger.warn(`Failed to load CISA KEV data: ${err.message}`);
    }
  }

  // ── NVD Rate Limiting ────────────────────────────────────────────────────

  /**
   * [FIX #11] Sleeps until at least NVD_MIN_INTERVAL_MS has elapsed
   * since the previous NVD request, then updates the timestamp.
   */
  private async enforceNvdRateLimit(): Promise<void> {
    const now     = Date.now();
    const elapsed = now - this.lastNvdRequestTime;
    if (elapsed < this.NVD_MIN_INTERVAL_MS) {
      await new Promise(resolve => setTimeout(resolve, this.NVD_MIN_INTERVAL_MS - elapsed));
    }
    this.lastNvdRequestTime = Date.now();
  }

  // ── Cache Eviction ───────────────────────────────────────────────────────

  /**
   * [FIX #28] Evicts the oldest 20% of cache entries when the Map exceeds
   * MAX_CACHE_SIZE. JavaScript Maps iterate in insertion order, so the first
   * keys are always the oldest.
   */
  private evictCacheIfNeeded<K, V>(cache: Map<K, V>): void {
    if (cache.size >= this.MAX_CACHE_SIZE) {
      const evictCount = Math.floor(this.MAX_CACHE_SIZE * 0.2);
      let deleted = 0;
      for (const key of cache.keys()) {
        if (deleted >= evictCount) break;
        cache.delete(key);
        deleted++;
      }
      this.logger.debug(`Cache eviction: removed ${deleted} stale entries`);
    }
  }

  // ── EPSS ─────────────────────────────────────────────────────────────────

  private async getEpssScore(cveId: string): Promise<number> {
    if (this.epssCache.has(cveId)) return this.epssCache.get(cveId)!;

    try {
      const response = await axios.get(`${this.EPSS_BASE_URL}?cve=${cveId}`, { timeout: 5000 });
      if (response.data?.data?.length > 0) {
        const score = parseFloat(response.data.data[0].epss);
        this.evictCacheIfNeeded(this.epssCache);
        this.epssCache.set(cveId, score);
        return score;
      }
    } catch (err: any) {
      this.logger.debug(`Failed to fetch EPSS for ${cveId}: ${err.message}`);
    }
    return 0;
  }

  // ── Main Enrichment ───────────────────────────────────────────────────────

  /**
   * Enrich a vulnerability with real-world threat intelligence.
   * Queries NVD for CVE details, cross-references CISA KEV, and fetches EPSS scores.
   */
  async enrichVulnerability(vuln: Vulnerability): Promise<{
    cve_id: string | null;
    exploit_available: boolean;
    threat_score: number;
  }> {
    let cve_id: string | null = null;
    let exploit_available     = false;
    let threat_score          = vuln.cvss_score ?? 5.0;

    try {
      const keyword = encodeURIComponent(vuln.title.substring(0, 50));

      let cveData: any = null;

      if (this.nvdCache.has(keyword)) {
        // Cache hit — no API call needed
        cveData = this.nvdCache.get(keyword);
      } else {
        // [FIX #11] Respect rate limit before calling NVD
        await this.enforceNvdRateLimit();

        const nvdUrl = `${this.NVD_BASE_URL}?keywordSearch=${keyword}&resultsPerPage=1`;
        const response = await axios.get(nvdUrl, {
          headers: process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {},
          timeout: 8000,
        });

        if (response.data?.vulnerabilities?.length > 0) {
          cveData = response.data.vulnerabilities[0].cve;
          this.evictCacheIfNeeded(this.nvdCache);
          this.nvdCache.set(keyword, cveData);
        }
      }

      if (cveData) {
        cve_id       = cveData.id;
        threat_score = cveData.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? threat_score;

        // 1. CISA KEV check — confirmed actively exploited
        if (cve_id && this.cisaKevMap.has(cve_id)) {
          exploit_available = true;
          // [FIX #19] Clamp immediately after each boost
          threat_score = Math.min(threat_score * 1.2, 10.0);
        }

        // 2. EPSS check — probabilistic exploitation risk
        if (cve_id) {
          const epssScore = await this.getEpssScore(cve_id);
          if (epssScore > 0.5) {
            exploit_available = true;
            // [FIX #19] Compute remaining headroom, then add bounded boost
            const headroom = 10.0 - threat_score;
            const boost    = Math.min(epssScore * 2, headroom);
            threat_score   = Math.min(threat_score + boost, 10.0);
          }
        }
      } else {
        // Heuristic fallback when NVD returns no results
        if (vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH') {
          exploit_available = vuln.title.toLowerCase().includes('rce')
                           || vuln.title.toLowerCase().includes('sql');
          if (exploit_available) {
            threat_score = Math.min(threat_score + 1.0, 10.0);
          }
        }
      }
    } catch (err: any) {
      this.logger.warn(`Failed to fetch Threat Intel for "${vuln.title}": ${err.message}`);
      // Conservative fallback
      if (vuln.severity === 'CRITICAL' || vuln.title.toLowerCase().includes('sql')) {
        exploit_available = true;
      }
    }

    return {
      cve_id,
      exploit_available,
      // [FIX #19] Final safety clamp — should already be ≤ 10 but belt-and-suspenders
      threat_score: Math.min(threat_score, 10.0),
    };
  }
}
