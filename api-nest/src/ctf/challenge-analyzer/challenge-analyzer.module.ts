import { Module } from '@nestjs/common';
import { ChallengeClassifierService } from './services/challenge-classifier.service';
import { AiHintGeneratorService } from './services/ai-hint-generator.service';
import { LearningRecommendationService } from './services/learning-recommendation.service';
import { ChallengeAnalyzerService } from './services/challenge-analyzer.service';
import { AdvancedCodeAnalyzerService } from './services/advanced-code-analyzer.service';

@Module({
  providers: [
    ChallengeClassifierService,
    AiHintGeneratorService,
    LearningRecommendationService,
    ChallengeAnalyzerService,
    AdvancedCodeAnalyzerService,
  ],
  exports: [ChallengeAnalyzerService, AdvancedCodeAnalyzerService],
})
export class ChallengeAnalyzerModule {}
