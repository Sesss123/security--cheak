import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class AiHintGeneratorService {
  private readonly logger = new Logger(AiHintGeneratorService.name);

  generateHints(category: string, description: string): string[] {
    this.logger.debug('Generating AI hints');
    if (category === 'Web') {
      return ['Look closely at the source code for hidden comments.', 'Check the robots.txt file.'];
    }
    return ['Try standard analysis tools first.'];
  }
}
