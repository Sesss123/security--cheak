import { Injectable, Logger } from '@nestjs/common';
import OpenAI from 'openai';
import { AgentPayload } from './interfaces/agent-payload.interface';

@Injectable()
export class ReconAgent {
  private readonly client: OpenAI;
  private readonly logger = new Logger(ReconAgent.name);
  private readonly MODEL = 'llama3-8b-8192';

  constructor() {
    this.client = new OpenAI({
      apiKey: process.env.GROQ_API_KEY || process.env.CLAUDE_API_KEY,
      baseURL: 'https://api.groq.com/openai/v1',
    });
  }

  async process(payload: AgentPayload): Promise<AgentPayload> {
    this.logger.log(`Starting Recon analysis for ${payload.context.targetUrl}`);
    
    const vulnSummaries = payload.context.rawVulns.map(v => `${v.title} (${v.severity})`).join(', ');

    const prompt = `You are a Reconnaissance AI Agent. Analyze the following discovered vulnerabilities for the target ${payload.context.targetUrl}.
    
Vulnerabilities:
${vulnSummaries}

Based on this, infer the probable technologies used, likely open ports, and analyze the overall attack surface area.
Respond ONLY with a valid JSON object, no markdown:
{
  "technologies": ["React", "Express", "PostgreSQL", "..."],
  "openPorts": [80, 443],
  "surfaceAreaAnalysis": "Brief analysis of the exposed attack surface based on findings."
}`;

    try {
      const response = await this.client.chat.completions.create({
        model: this.MODEL,
        messages: [{ role: 'user', content: prompt }],
        response_format: { type: 'json_object' },
      });

      const text = response.choices[0]?.message?.content || '{}';
      const clean = text.replace(/```json|```/g, '').trim();
      
      payload.recon = JSON.parse(clean);
    } catch (err) {
      this.logger.error('Recon AI Error:', err);
      payload.recon = { technologies: [], openPorts: [], surfaceAreaAnalysis: 'Analysis failed.' };
    }
    return payload;
  }
}
