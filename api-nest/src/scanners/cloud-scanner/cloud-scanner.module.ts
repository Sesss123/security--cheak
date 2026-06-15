import { Module } from '@nestjs/common';
import { AwsScannerService } from './services/aws-scanner.service';
import { AzureScannerService } from './services/azure-scanner.service';
import { GcpScannerService } from './services/gcp-scanner.service';
import { IamAnalyzerService } from './services/iam-analyzer.service';
import { NetworkAnalyzerService } from './services/network-analyzer.service';
import { StorageAnalyzerService } from './services/storage-analyzer.service';
import { CloudRiskScoringService } from './services/cloud-risk-scoring.service';

@Module({
  providers: [
    AwsScannerService,
    AzureScannerService,
    GcpScannerService,
    IamAnalyzerService,
    NetworkAnalyzerService,
    StorageAnalyzerService,
    CloudRiskScoringService,
  ],
  exports: [
    AwsScannerService,
    AzureScannerService,
    GcpScannerService,
    IamAnalyzerService,
    NetworkAnalyzerService,
    StorageAnalyzerService,
    CloudRiskScoringService,
  ],
})
export class CloudScannerModule {}
