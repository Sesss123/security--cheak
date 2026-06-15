import { Module } from '@nestjs/common';
import { ImageAnalysisService } from './services/image-analysis.service';
import { SecretDetectionService } from './services/secret-detection.service';
import { PackageRiskAnalyzer } from './services/package-risk.analyzer';
import { KubernetesAnalyzer } from './services/kubernetes.analyzer';
import { ContainerRiskScorer } from './services/container-risk.scorer';
import { ContainerReportGenerator } from './services/container-report.generator';

@Module({
  providers: [
    ImageAnalysisService,
    SecretDetectionService,
    PackageRiskAnalyzer,
    KubernetesAnalyzer,
    ContainerRiskScorer,
    ContainerReportGenerator,
  ],
  exports: [
    ImageAnalysisService,
    SecretDetectionService,
    PackageRiskAnalyzer,
    KubernetesAnalyzer,
    ContainerRiskScorer,
    ContainerReportGenerator,
  ],
})
export class ContainerScannerModule {}
