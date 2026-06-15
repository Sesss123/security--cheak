import { Controller, Post, Body, UploadedFile, UseInterceptors } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { SubdomainDiscoveryService } from './recon/services/subdomain-discovery.service';
import { RagAnalysisService } from './knowledge-base/services/rag-analysis.service';
import { FileAnalysisService } from './forensics/services/file-analysis.service';

@Controller('ctf')
export class CtfController {
  constructor(
    private readonly reconService: SubdomainDiscoveryService,
    private readonly ragService: RagAnalysisService,
    private readonly forensicsService: FileAnalysisService,
  ) {}

  @Post('recon/subdomains')
  async discoverSubdomains(@Body() data: { domain: string }) {
    return this.reconService.discover(data.domain);
  }

  @Post('rag/query')
  async queryKnowledgeBase(@Body() data: { query: string }) {
    return this.ragService.analyze(data.query);
  }

  @Post('forensics/upload')
  @UseInterceptors(FileInterceptor('file'))
  async uploadForensicsFile(@UploadedFile() file: Express.Multer.File) {
    return this.forensicsService.analyze(file.buffer);
  }
}
