import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class LearningRecommendationService {
  private readonly logger = new Logger(LearningRecommendationService.name);

  recommend(category: string): string[] {
    this.logger.debug('Recommending learning resources');
    if (category === 'Web') {
      return ['OWASP Top 10', 'PortSwigger Web Security Academy'];
    }
    if (category === 'Crypto') {
      return ['Cryptopals Crypto Challenges'];
    }
    return ['CTF101 Reference Guide'];
  }
}
