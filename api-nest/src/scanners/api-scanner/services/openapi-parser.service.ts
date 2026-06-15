import { Injectable, Logger } from '@nestjs/common';
import { ApiEndpoint } from '../dtos/api-finding.dto';

@Injectable()
export class OpenApiParserService {
  private readonly logger = new Logger(OpenApiParserService.name);

  parse(schemaStr: string): ApiEndpoint[] {
    this.logger.debug('Parsing OpenAPI/Swagger schema');
    const endpoints: ApiEndpoint[] = [];
    try {
      const schema = JSON.parse(schemaStr);
      if (schema.paths) {
        for (const [path, methods] of Object.entries(schema.paths)) {
          for (const [method, details] of Object.entries(methods as any)) {
            endpoints.push({
              method: method.toUpperCase(),
              path,
              parameters: (details as any).parameters || [],
              security: (details as any).security || schema.security || [],
            });
          }
        }
      }
    } catch (e) {
      this.logger.error('Failed to parse OpenAPI schema', e);
    }
    return endpoints;
  }
}
