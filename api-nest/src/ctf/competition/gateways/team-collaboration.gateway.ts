import { WebSocketGateway, WebSocketServer, SubscribeMessage, MessageBody } from '@nestjs/websockets';
import { Server } from 'socket.io';
import { Logger } from '@nestjs/common';
import { TimelineService } from '../services/timeline.service';

@WebSocketGateway({ cors: true })
export class TeamCollaborationGateway {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(TeamCollaborationGateway.name);

  constructor(private readonly timeline: TimelineService) {}

  @SubscribeMessage('teamMessage')
  handleMessage(@MessageBody() data: any): void {
    this.logger.debug(`Received team message: ${JSON.stringify(data)}`);
    this.server.emit(`team_${data.teamId}`, data);
    this.timeline.logEvent(data.teamId, 'Message Sent');
  }
}
