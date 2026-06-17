import { WebSocketGateway, WebSocketServer, OnGatewayConnection, OnGatewayDisconnect } from '@nestjs/websockets';
import { Server, WebSocket } from 'ws';
import { Injectable, Logger } from '@nestjs/common';
import { WsEvent } from '../types';
import * as jwt from 'jsonwebtoken';

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

    /**
     * [FIX #29] WebSocket JWT auth — Authorization header ONLY.
     *
     * The previous code accepted the token via the URL query string:
     *   ws://host/ws?scanId=xxx&token=yyy
     * This causes the token to appear in:
     *   - Web server access logs
     *   - Browser history
     *   - Referrer headers sent to third-party scripts
     *
     * Fix: accept ONLY the "Authorization: Bearer <token>" header.
     * Frontend must send it via WebSocket sub-protocol or a custom header.
     * (WS browser API doesn't support custom headers natively — use a
     * one-time ticket system or Socket.IO auth payload for browser clients.)
     */
    try {
      const authHeader = req.headers['authorization'];
      const token = authHeader?.startsWith('Bearer ')
        ? authHeader.slice(7)
        : null;

      if (!token) throw new Error('Token missing — use Authorization: Bearer <token> header');
      jwt.verify(token, process.env.JWT_SECRET as string);
    } catch (err) {
      this.logger.warn(`Rejected unauthorized WS connection for scan: ${scanId}`);
      client.close(1008, 'Unauthorized');
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

  // [MEDIUM] Connection Cleanup
  public closeScanConnections(scanId: string): void {
    const clients = this.rooms.get(scanId);
    if (clients) {
      for (const client of clients) {
        if (client.readyState === WebSocket.OPEN) {
          client.close(1000, 'Scan finished or deleted');
        }
      }
      this.rooms.delete(scanId);
    }
  }
}
