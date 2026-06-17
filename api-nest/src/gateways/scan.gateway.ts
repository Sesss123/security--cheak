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
  private tickets = new Map<string, { userId: string; expiresAt: number }>();

  createTicket(userId: string): string {
    const ticket = Math.random().toString(36).substring(2) + Date.now().toString(36);
    this.tickets.set(ticket, {
      userId,
      expiresAt: Date.now() + 15 * 1000, // 15 seconds expiration
    });
    
    // Periodically clean up expired tickets to avoid memory leaks
    if (this.tickets.size > 100) {
      const now = Date.now();
      for (const [t, data] of this.tickets.entries()) {
        if (data.expiresAt < now) {
          this.tickets.delete(t);
        }
      }
    }

    return ticket;
  }

  handleConnection(client: WebSocket, ...args: any[]) {
    const req = args[0];
    const url = new URL(req.url, `http://${req.headers.host}`);
    const scanId = url.searchParams.get('scanId');
    const ticket = url.searchParams.get('ticket');

    if (!scanId) {
      client.close(1008, 'scanId required');
      return;
    }

    if (!ticket) {
      client.close(1008, 'ticket required');
      return;
    }

    // Verify ticket
    const ticketData = this.tickets.get(ticket);
    if (!ticketData || ticketData.expiresAt < Date.now()) {
      this.logger.warn(`Rejected invalid or expired WS ticket for scan: ${scanId}`);
      client.close(1008, 'Unauthorized');
      return;
    }

    // One-time use: delete ticket
    this.tickets.delete(ticket);

    this.logger.log(`WS connected for scan: ${scanId} (user: ${ticketData.userId})`);
    
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
