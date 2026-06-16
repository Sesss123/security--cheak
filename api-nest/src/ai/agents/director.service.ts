import { Injectable, Logger } from '@nestjs/common';
import { AgentPayload } from './interfaces/agent-payload.interface';
import { ReconAgent } from './recon.agent';
import { ThreatAgent } from './threat.agent';
import { ForensicsAgent } from './forensics.agent';
import { AttackChainAgent } from './attack-chain.agent';
import { SocAnalystAgent } from './soc-analyst.agent';
import { Vulnerability } from '../../types';

@Injectable()
export class DirectorService {
  private readonly logger = new Logger(DirectorService.name);

  constructor(
    private readonly reconAgent: ReconAgent,
    private readonly threatAgent: ThreatAgent,
    private readonly forensicsAgent: ForensicsAgent,
    private readonly attackChainAgent: AttackChainAgent,
    private readonly socAnalystAgent: SocAnalystAgent,
  ) {}

  async runSecurityAnalysis(targetUrl: string, scanId: string, rawVulns: Vulnerability[]): Promise<AgentPayload> {
    this.logger.log(`Director AI: Starting full security analysis pipeline for ${targetUrl}`);

    let payload: AgentPayload = {
      context: {
        targetUrl,
        scanId,
        rawVulns,
      }
    };

    // Stage 1: Recon & Threat
    payload = await this.reconAgent.process(payload);
    payload = await this.threatAgent.process(payload);

    // Stage 2: Forensics & Attack Chain
    payload = await this.forensicsAgent.process(payload);
    payload = await this.attackChainAgent.process(payload);

    // Stage 3: SOC Analyst Synthesis
    payload = await this.socAnalystAgent.process(payload);

    this.logger.log(`Director AI: Finished full security analysis pipeline for ${targetUrl}`);
    return payload;
  }
}
