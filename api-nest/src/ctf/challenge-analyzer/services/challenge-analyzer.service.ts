import { Injectable, Logger } from '@nestjs/common';
import { ChallengeAnalysis } from '../dtos/challenge-analysis.dto';
import { ChallengeClassifierService } from './challenge-classifier.service';
import { AiHintGeneratorService } from './ai-hint-generator.service';
import { LearningRecommendationService } from './learning-recommendation.service';

@Injectable()
export class ChallengeAnalyzerService {
  private readonly logger = new Logger(ChallengeAnalyzerService.name);

  constructor(
    private readonly classifier: ChallengeClassifierService,
    private readonly hintGenerator: AiHintGeneratorService,
    private readonly recommender: LearningRecommendationService,
  ) {}

  analyze(description: string): ChallengeAnalysis {
    const classification = this.classifier.classify(description);
    const hints = this.hintGenerator.generateHints(classification.category, description);
    const recommendations = this.recommender.recommend(classification.category);

    return {
      likelyCategory: classification.category,
      confidenceScore: classification.confidence,
      hints,
      recommendedInvestigationPath: [`Review ${classification.category} basics`, 'Apply generated hints'],
      learningReferences: recommendations,
    };
  }
}
