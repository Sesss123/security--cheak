import { Controller, Get } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';

@Controller('api/health')
export class HealthController {
  constructor(
    @InjectQueue('scan-jobs') private scanQueue: Queue,
  ) {}

  @Get()
  async getHealth() {
    try {
      // Check if we have active workers listening to this queue
      const workers = await this.scanQueue.getWorkers();
      const isWorkerOnline = workers && workers.length > 0;

      return {
        api: 'online',
        worker: isWorkerOnline ? 'online' : 'offline',
        activeWorkers: workers.length,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      return {
        api: 'online',
        worker: 'offline',
        activeWorkers: 0,
        error: error.message,
        timestamp: new Date().toISOString(),
      };
    }
  }
}
