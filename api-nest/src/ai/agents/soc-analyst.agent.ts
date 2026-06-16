import { Injectable, Logger } from '@nestjs/common';
import OpenAI from 'openai';
import { AgentPayload } from './interfaces/agent-payload.interface';

@Injectable()
export class SocAnalystAgent {
  private readonly client: OpenAI;
  private readonly logger = new Logger(SocAnalystAgent.name);
  private readonly MODEL = 'llama3-8b-8192';

  constructor() {
    this.client = new OpenAI({
      apiKey: process.env.GROQ_API_KEY || process.env.CLAUDE_API_KEY,
      baseURL: 'https://api.groq.com/openai/v1',
    });
  }

  async process(payload: AgentPayload): Promise<AgentPayload> {
    this.logger.log(`Starting SOC Analyst analysis for ${payload.context.targetUrl}`);
    
    const contextStr = JSON.stringify({
      recon: payload.recon,
      threat: payload.threat,
      forensics: payload.forensics,
      attackChain: payload.attackChain,
      totalVulns: payload.context.rawVulns.length
    });

    const prompt = `You are the Lead SOC Analyst AI. Review all data gathered by your sub-agents: ${contextStr}.
    
Synthesize this into a final Executive Summary, determine the Risk Rating, and provide top recommendations for the target ${payload.context.targetUrl}.
Respond ONLY with a valid JSON object, no markdown:
{
  "executiveSummary": "A comprehensive 3-sentence summary of the security posture and immediate risks.",
  "riskRating": "CRITICAL, HIGH, MEDIUM, or LOW",
  "topRecommendations": ["1. Fix X", "2. Implement Y", "3. Monitor Z"],
  "attackPathDetails": "A narrative explaining the most critical attack path."
}`;

    try {
      const response = await this.client.chat.completions.create({
        model: this.MODEL,
        messages: [{ role: 'user', content: prompt }],
        response_format: { type: 'json_object' },
      });

      const text = response.choices[0]?.message?.content || '{}';
      const clean = text.replace(/```json|```/g, '').trim();
      
      payload.socAnalyst = JSON.parse(clean);
    } catch (err) {
      this.logger.error('SOC Analyst AI Error:', err);
      payload.socAnalyst = {
        executiveSummary: "Analysis failed due to an AI service error.",
        riskRating: "UNKNOWN",
        topRecommendations: [],
        attackPathDetails: "N/A"
      };
    }
    return payload;
  }
}
