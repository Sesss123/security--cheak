import { Injectable, Logger } from '@nestjs/common';
import OpenAI from 'openai';
import { Vulnerability, AiVulnAnalysis, AiReportSummary } from '../types';
import { ContextBuilderService } from '../ai/rag/services/context-builder.service';

@Injectable()
export class AiService {
  private readonly client: OpenAI;
  private readonly logger = new Logger(AiService.name);
  private readonly MODEL = 'llama3-8b-8192';

  constructor(private readonly contextBuilder: ContextBuilderService) {
    this.client = new OpenAI({
      apiKey: process.env.GROQ_API_KEY || process.env.CLAUDE_API_KEY,
      baseURL: 'https://api.groq.com/openai/v1',
    });
  }

  async analyzeVulnerability(
    vuln: Vulnerability & { cve_id?: string; exploit_available?: boolean },
    targetUrl: string,
  ): Promise<AiVulnAnalysis & { attack_path?: string[]; attack_probability?: string }> {
    const ragContext = await this.contextBuilder.buildVulnAnalysisContext(vuln);

    const prompt = `You are an elite AI SOC Analyst and Cybersecurity Consultant. Analyze this vulnerability and provide a detailed assessment including an Attack Path.

Target: ${targetUrl}
Vulnerability Title: ${vuln.title}
Severity: ${vuln.severity}
CVSS Score: ${vuln.cvss_score}
Category: ${vuln.category}
CVE ID: ${vuln.cve_id ?? 'None'}
Public Exploit Available: ${vuln.exploit_available ? 'YES' : 'NO'}
Description: ${vuln.description}
${ragContext}

Respond ONLY with a valid JSON object, no markdown, no preamble:
{
  "explanation": "Technical explanation of the vulnerability (2 sentences)",
  "business_impact": "Business risks if exploited (2 sentences)",
  "remediation_steps": [
    "Step 1: fix",
    "Step 2: fix"
  ],
  "attack_path": [
    "Reconnaissance: How attacker finds this",
    "Exploitation: How they exploit it",
    "Post-Exploitation: What they do next (e.g. Data Exfiltration)"
  ],
  "attack_probability": "HIGH, MEDIUM, or LOW",
  "fix_priority": 8
}

Note: If Public Exploit is YES, Attack Probability should usually be HIGH.`;

    try {
      const response = await this.client.chat.completions.create({
        model: this.MODEL,
        messages: [{ role: 'user', content: prompt }],
        response_format: { type: 'json_object' },
      });

      const text = response.choices[0]?.message?.content || '';
      const clean = text.replace(/```json|```/g, '').trim();
      return JSON.parse(clean) as AiVulnAnalysis;
    } catch (err) {
      this.logger.error('Groq AI Error:', err);
      return {
        explanation: vuln.description,
        business_impact:
          'This vulnerability may allow attackers to compromise the application.',
        remediation_steps: [
          vuln.remediation || 'Follow OWASP remediation guidelines.',
        ],
        code_example: null,
        fix_priority: this.severityToPriority(vuln.severity),
      };
    }
  }

  async generateExecutiveSummary(
    targetUrl: string,
    totalVulns: number,
    critical: number,
    high: number,
    medium: number,
    low: number,
    riskScore: number,
    topVulns: Vulnerability[],
  ): Promise<AiReportSummary> {
    const vulnSummary = topVulns
      .slice(0, 5)
      .map((v) => `- ${v.severity}: ${v.title}`)
      .join('\n');

    const prompt = `You are a cybersecurity consultant writing an executive summary for a security assessment report.

Target: ${targetUrl}
Overall Risk Score: ${riskScore.toFixed(1)}/10
Total Vulnerabilities: ${totalVulns}
  Critical: ${critical}
  High: ${high}
  Medium: ${medium}
  Low: ${low}

Top Findings:
${vulnSummary}

Write a concise executive summary for non-technical stakeholders.
Respond ONLY with valid JSON, no markdown:
{
  "executive_summary": "3-4 sentence executive summary covering overall security posture, key risks, and urgency",
  "risk_rating": "CRITICAL",
  "top_recommendations": [
    "Immediate action recommendation 1",
    "Short term recommendation 2",
    "Long term recommendation 3"
  ]
}

risk_rating must be one of: CRITICAL, HIGH, MEDIUM, LOW, MINIMAL`;

    try {
      const response = await this.client.chat.completions.create({
        model: this.MODEL,
        messages: [{ role: 'user', content: prompt }],
        response_format: { type: 'json_object' },
      });

      const text = response.choices[0]?.message?.content || '';
      const clean = text.replace(/```json|```/g, '').trim();
      return JSON.parse(clean) as AiReportSummary;
    } catch (err) {
      this.logger.error('Groq AI Error:', err);
      return {
        executive_summary: `Security assessment of ${targetUrl} identified ${totalVulns} vulnerabilities with a risk score of ${riskScore.toFixed(1)}/10. Immediate remediation of ${critical} critical and ${high} high severity issues is recommended.`,
        risk_rating: this.scoreToRating(riskScore),
        top_recommendations: [
          'Address all critical vulnerabilities immediately',
          'Implement security headers',
          'Conduct regular security assessments',
        ],
      };
    }
  }

  async chatAboutScan(
    scanId: string,
    vulns: Vulnerability[],
    userMessage: string,
    history: Array<{ role: 'user' | 'assistant'; content: string }>,
  ): Promise<string> {
    const ragContext = await this.contextBuilder.buildChatContext(userMessage);

    const context = `You are a cybersecurity expert assistant helping analyze security scan results.

Scan ID: ${scanId}
Current Scan Vulnerabilities found: ${vulns.length}
Current Scan Summary: ${vulns.map((v) => `${v.severity}: ${v.title}`).join(', ')}
${ragContext}

Answer the user's questions about these security findings. Use the Enterprise Knowledge Base if it contains relevant past fixes. Be helpful, technical, and precise.`;

    const messages: any[] = [
      { role: 'system', content: context },
      ...history,
      { role: 'user', content: userMessage },
    ];

    try {
      const response = await this.client.chat.completions.create({
        model: this.MODEL,
        messages,
      });

      return response.choices[0]?.message?.content || '';
    } catch (err) {
      this.logger.error('Groq AI Error:', err);
      return 'Sorry, I encountered an error connecting to Groq AI. Please check your API key.';
    }
  }

  private severityToPriority(severity: string): number {
    const map: Record<string, number> = {
      CRITICAL: 10,
      HIGH: 8,
      MEDIUM: 5,
      LOW: 3,
      INFO: 1,
    };
    return map[severity] ?? 5;
  }

  private scoreToRating(score: number): AiReportSummary['risk_rating'] {
    if (score >= 8) return 'CRITICAL';
    if (score >= 6) return 'HIGH';
    if (score >= 4) return 'MEDIUM';
    if (score >= 2) return 'LOW';
    return 'MINIMAL';
  }
}
