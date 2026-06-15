import { WebSocket } from 'ws';
import { WsEvent } from '../types';

// Map: scanId -> Set of connected WebSocket clients
class WebSocketManager {
  private rooms = new Map<string, Set<WebSocket>>();

  join(scanId: string, ws: WebSocket): void {
    if (!this.rooms.has(scanId)) {
      this.rooms.set(scanId, new Set());
    }
    this.rooms.get(scanId)!.add(ws);

    ws.on('close', () => this.leave(scanId, ws));
  }

  leave(scanId: string, ws: WebSocket): void {
    this.rooms.get(scanId)?.delete(ws);
    if (this.rooms.get(scanId)?.size === 0) {
      this.rooms.delete(scanId);
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

  broadcastAll(event: WsEvent): void {
    for (const clients of this.rooms.values()) {
      const payload = JSON.stringify(event);
      for (const client of clients) {
        if (client.readyState === WebSocket.OPEN) {
          client.send(payload);
        }
      }
    }
  }
}

export const wsManager = new WebSocketManager();
