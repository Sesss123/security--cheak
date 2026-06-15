import { WebSocketGateway, WebSocketServer, OnGatewayConnection, OnGatewayDisconnect } from '@nestjs/websockets';
import { Server, WebSocket } from 'ws';
import { Injectable, Logger } from '@nestjs/common';
import { WsEvent } from '../types';

@Injectable()
@WebSocketGateway({ path: '/ws' })
export class ScanGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(ScanGateway.name);
  private rooms = new Map<string, Set<WebSocket>>();

  handleConnection(client: WebSocket, ...args: any[]) {
    const req = args[0];
    const url = new URL(req.url, `http://${req.headers.host}`);
    const scanId = url.searchParams.get('scanId');

    if (!scanId) {
      client.close(1008, 'scanId required');
      return;
    }

    this.logger.log(`WS connected for scan: ${scanId}`);
    
    if (!this.rooms.has(scanId)) {
      this.rooms.set(scanId, new Set());
    }
    this.rooms.get(scanId)!.add(client);

    // attach scanId for disconnect
    (client as any).scanId = scanId;
  }

  handleDisconnect(client: WebSocket) {
    const scanId = (client as any).scanId;
    if (scanId) {
      this.rooms.get(scanId)?.delete(client);
      if (this.rooms.get(scanId)?.size === 0) {
        this.rooms.delete(scanId);
      }
    }
  }

  broadcast(scanId: string, event: WsEvent): void {
    const clients = this.rooms.get(scanId);
    if (!clients) return;

    const payload = JSON.stringify(event);
    for (const client of clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    }
  }
}
