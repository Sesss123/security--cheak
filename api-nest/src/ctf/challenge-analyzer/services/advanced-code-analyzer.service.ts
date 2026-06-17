import { Injectable, Logger } from '@nestjs/common';
import OpenAI from 'openai';
import { AdvancedCodeAnalysis } from '../dtos/advanced-analysis.dto';

@Injectable()
export class AdvancedCodeAnalyzerService {
  private readonly client: OpenAI;
  private readonly logger = new Logger(AdvancedCodeAnalyzerService.name);
  private readonly MODEL = 'llama3-8b-8192';

  constructor() {
    this.client = new OpenAI({
      apiKey: process.env.GROQ_API_KEY || process.env.CLAUDE_API_KEY,
      baseURL: 'https://api.groq.com/openai/v1',
    });
  }

  async analyze(code: string): Promise<AdvancedCodeAnalysis> {
    this.logger.log('Running Advanced Code Analysis via AI');

    const prompt = `You are an elite Cybersecurity CTF Analyst and Senior Software Architect. 
Please perform an advanced, in-depth analysis of the following source code snippet.

Analyze the code and categorize your findings precisely into the following 8 areas.
Focus on identifying security vulnerabilities, logic bugs, architecture flaws, and performance bottlenecks.

Respond ONLY with a valid JSON object matching this structure:
{
  "codeQuality": ["string array of code quality findings"],
  "bugs": ["string array of general bugs"],
  "logicFlaws": ["string array of logic flaws"],
  "performanceIssues": ["string array of performance bottlenecks"],
  "securityIssues": ["string array of security vulnerabilities"],
  "falsePositives": ["string array of things that might look like bugs but are actually safe/false positives"],
  "falseNegatives": ["string array of hidden issues that a typical scanner might miss"],
  "architectureProblems": ["string array of architectural or structural design problems"]
}

Source Code to Analyze:
\`\`\`
${code}
\`\`\`
`;

    try {
      const response = await this.client.chat.completions.create({
        model: this.MODEL,
        messages: [{ role: 'user', content: prompt }],
        response_format: { type: 'json_object' },
      });

      const text = response.choices[0]?.message?.content || '';
      const clean = text.replace(/```json|```/g, '').trim();
      return JSON.parse(clean) as AdvancedCodeAnalysis;
    } catch (error) {
      this.logger.error('Failed to perform advanced code analysis', error);
      // Return a safe fallback to prevent crashing
      return {
        codeQuality: ['Error analyzing code quality.'],
        bugs: ['Error analyzing bugs.'],
        logicFlaws: ['Error analyzing logic flaws.'],
        performanceIssues: ['Error analyzing performance.'],
        securityIssues: ['Error connecting to AI service for security analysis.'],
        falsePositives: [],
        falseNegatives: [],
        architectureProblems: [],
      };
    }
  }
}
