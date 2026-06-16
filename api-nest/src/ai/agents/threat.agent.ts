import { Injectable, Logger } from '@nestjs/common';
import OpenAI from 'openai';
import { AgentPayload } from './interfaces/agent-payload.interface';

@Injectable()
export class ThreatAgent {
  private readonly client: OpenAI;
  private readonly logger = new Logger(ThreatAgent.name);
  private readonly MODEL = 'llama3-8b-8192';

  constructor() {
    this.client = new OpenAI({
      apiKey: process.env.GROQ_API_KEY || process.env.CLAUDE_API_KEY,
      baseURL: 'https://api.groq.com/openai/v1',
    });
  }

  async process(payload: AgentPayload): Promise<AgentPayload> {
    this.logger.log(`Starting Threat analysis for ${payload.context.targetUrl}`);
    
    const reconData = payload.recon ? JSON.stringify(payload.recon) : 'No Recon Data';
    const vulnSummaries = payload.context.rawVulns.map(v => `${v.title}`).join(', ');

    const prompt = `You are a Threat Intelligence AI Agent. Given the reconnaissance data and vulnerabilities for ${payload.context.targetUrl}, identify matched CVEs and potential Threat Actors (APT groups) who typically exploit these.
    
Recon Data: ${reconData}
Vulnerabilities: ${vulnSummaries}

Respond ONLY with a valid JSON object, no markdown:
{
  "matchedCVEs": ["CVE-2021-44228", "CVE-..."],
  "threatActors": ["APT29", "Lazarus Group", "..."],
  "threatSummary": "Brief summary of the threat landscape."
}`;

    try {
      const response = await this.client.chat.completions.create({
        model: this.MODEL,
        messages: [{ role: 'user', content: prompt }],
        response_format: { type: 'json_object' },
      });

      const text = response.choices[0]?.message?.content || '{}';
      const clean = text.replace(/```json|```/g, '').trim();
      
      payload.threat = JSON.parse(clean);
    } catch (err) {
      this.logger.error('Threat AI Error:', err);
      payload.threat = { matchedCVEs: [], threatActors: [], threatSummary: 'Analysis failed.' };
    }
    return payload;
  }
}
