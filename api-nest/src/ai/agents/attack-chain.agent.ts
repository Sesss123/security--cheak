import { Injectable, Logger } from '@nestjs/common';
import OpenAI from 'openai';
import { AgentPayload } from './interfaces/agent-payload.interface';

@Injectable()
export class AttackChainAgent {
  private readonly client: OpenAI;
  private readonly logger = new Logger(AttackChainAgent.name);
  private readonly MODEL = 'llama3-8b-8192';

  constructor() {
    this.client = new OpenAI({
      apiKey: process.env.GROQ_API_KEY || process.env.CLAUDE_API_KEY,
      baseURL: 'https://api.groq.com/openai/v1',
    });
  }

  async process(payload: AgentPayload): Promise<AgentPayload> {
    this.logger.log(`Starting Attack Chain analysis for ${payload.context.targetUrl}`);
    
    const reconData = payload.recon ? JSON.stringify(payload.recon) : 'None';
    const threatData = payload.threat ? JSON.stringify(payload.threat) : 'None';
    const vulnSummaries = payload.context.rawVulns.map(v => `${v.title}`).join(', ');

    const prompt = `You are an Attack Chain AI Agent. Connect the vulnerabilities (${vulnSummaries}), Recon Data (${reconData}), and Threat Data (${threatData}) into an Attack Chain.
    
Map the findings to MITRE ATT&CK techniques and outline the Kill Chain stages.
Respond ONLY with a valid JSON object, no markdown:
{
  "attackPaths": ["Path 1: XSS -> Session Hijack -> Admin Access", "..."],
  "killChainStages": ["Reconnaissance", "Initial Access", "Privilege Escalation", "..."],
  "mitreTechniques": ["T1190 Exploit Public-Facing Application", "..."]
}`;

    try {
      const response = await this.client.chat.completions.create({
        model: this.MODEL,
        messages: [{ role: 'user', content: prompt }],
        response_format: { type: 'json_object' },
      });

      const text = response.choices[0]?.message?.content || '{}';
      const clean = text.replace(/```json|```/g, '').trim();
      
      payload.attackChain = JSON.parse(clean);
    } catch (err) {
      this.logger.error('Attack Chain AI Error:', err);
      payload.attackChain = { attackPaths: [], killChainStages: [], mitreTechniques: [] };
    }
    return payload;
  }
}
