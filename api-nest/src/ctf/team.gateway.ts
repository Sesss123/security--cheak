import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, WebSocket } from 'ws';

@WebSocketGateway({ path: '/team-ws' })
export class TeamGateway {
  @WebSocketServer()
  server: Server;

  private teamFlags = new Map<string, string[]>();
  private teamNotes = new Map<string, any[]>();
  
  // Custom room implementation for native WebSockets
  private teamRooms = new Map<string, Set<WebSocket>>();

  @SubscribeMessage('joinTeam')
  handleJoinTeam(
    @MessageBody() data: { teamId: string; username: string },
    @ConnectedSocket() client: WebSocket,
  ) {
    if (!this.teamRooms.has(data.teamId)) {
      this.teamRooms.set(data.teamId, new Set());
    }
    this.teamRooms.get(data.teamId)!.add(client);
    
    // Save teamId on client for disconnect cleanup if needed
    (client as any).teamId = data.teamId;
    
    const flags = this.teamFlags.get(data.teamId) || [];
    const notes = this.teamNotes.get(data.teamId) || [];
    
    client.send(JSON.stringify({ event: 'syncState', data: { flags, notes } }));
    
    this.broadcastToTeam(data.teamId, 'userJoined', { username: data.username, time: new Date() }, client);
    
    return { event: 'joined', data: { teamId: data.teamId } };
  }

  @SubscribeMessage('submitFlag')
  handleFlagSubmission(
    @MessageBody() data: { teamId: string; flag: string; challengeId: string; username: string },
    @ConnectedSocket() client: WebSocket,
  ) {
    const flags = this.teamFlags.get(data.teamId) || [];
    if (!flags.includes(data.flag)) {
        flags.push(data.flag);
        this.teamFlags.set(data.teamId, flags);
        
        this.broadcastToTeam(data.teamId, 'flagCaptured', {
            flag: data.flag,
            challengeId: data.challengeId,
            username: data.username,
            time: new Date()
        });
    }
  }

  @SubscribeMessage('addNote')
  handleAddNote(
    @MessageBody() data: { teamId: string; note: string; username: string },
    @ConnectedSocket() client: WebSocket,
  ) {
    const notes = this.teamNotes.get(data.teamId) || [];
    const newNote = { id: Date.now().toString(), text: data.note, author: data.username, time: new Date() };
    
    notes.push(newNote);
    this.teamNotes.set(data.teamId, notes);
    
    this.broadcastToTeam(data.teamId, 'noteAdded', newNote);
  }

  private broadcastToTeam(teamId: string, eventName: string, payload: any, excludeClient?: WebSocket) {
    const room = this.teamRooms.get(teamId);
    if (!room) return;
    
    const message = JSON.stringify({ event: eventName, data: payload });
    for (const client of room) {
      if (client !== excludeClient && client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    }
  }
}
