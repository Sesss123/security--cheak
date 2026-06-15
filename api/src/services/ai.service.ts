import OpenAI from 'openai';
import { Vulnerability, AiVulnAnalysis, AiReportSummary } from '../types';

const client = new OpenAI({
  apiKey: process.env.GROQ_API_KEY || process.env.CLAUDE_API_KEY, // Use whichever key is provided
  baseURL: 'https://api.groq.com/openai/v1',
});

// Groq fast model
const MODEL = 'llama3-8b-8192';

// ── Vulnerability Analysis ────────────────────────────────────

export async function analyzeVulnerability(
  vuln: Vulnerability,
  targetUrl: string
): Promise<AiVulnAnalysis> {
  const isCtf = vuln.title.includes('🚩') || vuln.title.includes('CTF') || vuln.title.includes('FLAG') || vuln.title.includes('Hidden Path') || vuln.category === 'InformationDisclosure';
  
  const prompt = isCtf 
  ? `You are an expert Capture The Flag (CTF) Mentor. Analyze this CTF finding and provide subtle, educational hints to help the player learn without directly giving them the flag.

Target: ${targetUrl}
CTF Finding Title: ${vuln.title}
Evidence: ${JSON.stringify(vuln.evidence.slice(0, 2))}
Description: ${vuln.description}

Respond ONLY with a valid JSON object, no markdown:
{
  "explanation": "Explain what this finding usually means in the context of a CTF challenge (2-3 sentences)",
  "business_impact": "Explain how this misconfiguration happens in the real world (2 sentences)",
  "remediation_steps": [
    "Hint 1: A very subtle push in the right direction",
    "Hint 2: A slightly more direct hint if they are stuck",
    "Hint 3: The methodology to exploit this (without giving the exact command/flag)"
  ],
  "code_example": null,
  "fix_priority": 10,
  "attack_path": ["Reconnaissance", "Discovery", "Exploitation"],
  "attack_probability": "HIGH"
}`
  : `You are a senior cybersecurity expert. Analyze this vulnerability found during a security scan and provide a detailed assessment.

Target: ${targetUrl}
Vulnerability Title: ${vuln.title}
Severity: ${vuln.severity}
CVSS Score: ${vuln.cvss_score}
Category: ${vuln.category}
OWASP: ${vuln.owasp_category ?? 'N/A'}
CWE: ${vuln.cwe_id ? `CWE-${vuln.cwe_id}` : 'N/A'}
Affected URL: ${vuln.affected_url}
Description: ${vuln.description}
Evidence: ${JSON.stringify(vuln.evidence.slice(0, 2))}

Respond ONLY with a valid JSON object, no markdown, no preamble:
{
  "explanation": "Clear, technical explanation of what this vulnerability is and how it works (2-3 sentences)",
  "business_impact": "Specific business risks if exploited - data breach, financial loss, reputation damage etc (2 sentences)",
  "remediation_steps": [
    "Step 1: specific actionable fix",
    "Step 2: specific actionable fix",
    "Step 3: verify the fix"
  ],
  "code_example": "Optional: show vulnerable code vs fixed code if applicable, or null",
  "fix_priority": 8,
  "attack_path": ["Initial Access", "Execution", "Exfiltration"],
  "attack_probability": "MEDIUM"
}

fix_priority is 1-10 (10 = fix immediately, 1 = low priority).`;

  try {
    const response = await client.chat.completions.create({
      model: MODEL,
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: 'json_object' }
    });

    const text = response.choices[0]?.message?.content || '';
    const clean = text.replace(/```json|```/g, '').trim();
    return JSON.parse(clean) as AiVulnAnalysis;
  } catch (err) {
    console.error('Groq AI Error:', err);
    return {
      explanation: vuln.description,
      business_impact: 'This vulnerability may allow attackers to compromise the application.',
      remediation_steps: [vuln.remediation || 'Follow OWASP remediation guidelines.'],
      code_example: null,
      fix_priority: severityToPriority(vuln.severity),
    };
  }
}

// ── Executive Summary Generation ─────────────────────────────

export async function generateExecutiveSummary(
  targetUrl: string,
  totalVulns: number,
  critical: number,
  high: number,
  medium: number,
  low: number,
  riskScore: number,
  topVulns: Vulnerability[]
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
    const response = await client.chat.completions.create({
      model: MODEL,
      messages: [{ role: 'user', content: prompt }],
      response_format: { type: 'json_object' }
    });

    const text = response.choices[0]?.message?.content || '';
    const clean = text.replace(/```json|```/g, '').trim();
    return JSON.parse(clean) as AiReportSummary;
  } catch (err) {
    console.error('Groq AI Error:', err);
    return {
      executive_summary: `Security assessment of ${targetUrl} identified ${totalVulns} vulnerabilities with a risk score of ${riskScore.toFixed(1)}/10. Immediate remediation of ${critical} critical and ${high} high severity issues is recommended.`,
      risk_rating: scoreToRating(riskScore),
      top_recommendations: ['Address all critical vulnerabilities immediately', 'Implement security headers', 'Conduct regular security assessments'],
    };
  }
}

// ── Chat with AI about scan results ──────────────────────────

export async function chatAboutScan(
  scanId: string,
  vulns: Vulnerability[],
  userMessage: string,
  history: Array<{ role: 'user' | 'assistant'; content: string }>
): Promise<string> {
  const context = `You are a cybersecurity expert assistant helping analyze security scan results.

Scan ID: ${scanId}
Vulnerabilities found: ${vulns.length}
Summary: ${vulns.map((v) => `${v.severity}: ${v.title}`).join(', ')}

Answer the user's questions about these security findings. Be helpful, technical, and precise.`;

  const messages: any[] = [
    { role: 'system', content: context },
    ...history,
    { role: 'user', content: userMessage },
  ];

  try {
    const response = await client.chat.completions.create({
      model: MODEL,
      messages,
    });

    return response.choices[0]?.message?.content || '';
  } catch (err) {
    console.error('Groq AI Error:', err);
    return 'Sorry, I encountered an error connecting to Groq AI. Please check your API key.';
  }
}

// ── Helpers ───────────────────────────────────────────────────

function severityToPriority(severity: string): number {
  const map: Record<string, number> = {
    CRITICAL: 10, HIGH: 8, MEDIUM: 5, LOW: 3, INFO: 1,
  };
  return map[severity] ?? 5;
}

function scoreToRating(score: number): AiReportSummary['risk_rating'] {
  if (score >= 8) return 'CRITICAL';
  if (score >= 6) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score >= 2) return 'LOW';
  return 'MINIMAL';
}
