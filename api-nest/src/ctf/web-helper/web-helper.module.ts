import { Module } from '@nestjs/common';
import { CookieAnalyzerService } from './services/cookie-analyzer.service';
import { JwtInspectorService } from './services/jwt-inspector.service';
import { Base64AnalysisService } from './services/base64-analysis.service';
import { UrlUtilityService } from './services/url-utility.service';
import { HashIdentifierService } from './services/hash-identifier.service';
import { HttpInspectorService } from './services/http-inspector.service';

@Module({
  providers: [
    CookieAnalyzerService,
    JwtInspectorService,
    Base64AnalysisService,
    UrlUtilityService,
    HashIdentifierService,
    HttpInspectorService,
  ],
  exports: [
    CookieAnalyzerService,
    JwtInspectorService,
    Base64AnalysisService,
    UrlUtilityService,
    HashIdentifierService,
    HttpInspectorService,
  ],
})
export class WebHelperModule {}
