import { Injectable, Logger } from '@nestjs/common';
import OpenAI from 'openai';
import { AgentPayload } from './interfaces/agent-payload.interface';

@Injectable()
export class ForensicsAgent {
  private readonly client: OpenAI;
  private readonly logger = new Logger(ForensicsAgent.name);
  private readonly MODEL = 'llama3-8b-8192';

  constructor() {
    this.client = new OpenAI({
      apiKey: process.env.GROQ_API_KEY || process.env.CLAUDE_API_KEY,
      baseURL: 'https://api.groq.com/openai/v1',
    });
  }

  async process(payload: AgentPayload): Promise<AgentPayload> {
    this.logger.log(`Starting Forensics analysis for ${payload.context.targetUrl}`);
    
    const vulnSummaries = payload.context.rawVulns.map(v => `${v.title}`).join(', ');

    const prompt = `You are a Forensics AI Agent. Given the target ${payload.context.targetUrl} and found vulnerabilities: ${vulnSummaries}, generate potential Indicators of Compromise (IOCs) that a defender should look for, and a hypothetical timeline of an attack.
    
Respond ONLY with a valid JSON object, no markdown:
{
  "iocs": ["Suspicious IPs: x.x.x.x", "File hashes: ...", "Log patterns: ..."],
  "timeline": "Hypothetical timeline of how an attacker might have breached this system.",
  "evidenceSummary": "What evidence should be collected (e.g. PCAP, memory dump)."
}`;

    try {
      const response = await this.client.chat.completions.create({
        model: this.MODEL,
        messages: [{ role: 'user', content: prompt }],
        response_format: { type: 'json_object' },
      });

      const text = response.choices[0]?.message?.content || '{}';
      const clean = text.replace(/```json|```/g, '').trim();
      
      payload.forensics = JSON.parse(clean);
    } catch (err) {
      this.logger.error('Forensics AI Error:', err);
      payload.forensics = { iocs: [], timeline: 'Failed to generate timeline.', evidenceSummary: 'Analysis failed.' };
    }
    return payload;
  }
}
