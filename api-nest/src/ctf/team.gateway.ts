import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
  namespace: 'team',
})
export class TeamGateway {
  @WebSocketServer()
  server: Server;

  private teamFlags = new Map<string, string[]>();
  private teamNotes = new Map<string, any[]>();

  @SubscribeMessage('joinTeam')
  handleJoinTeam(
    @MessageBody() data: { teamId: string; username: string },
    @ConnectedSocket() client: Socket,
  ) {
    client.join(data.teamId);
    
    // Send current state to newly joined user
    const flags = this.teamFlags.get(data.teamId) || [];
    const notes = this.teamNotes.get(data.teamId) || [];
    
    client.emit('syncState', { flags, notes });
    
    // Notify others
    client.to(data.teamId).emit('userJoined', { username: data.username, time: new Date() });
    return { event: 'joined', teamId: data.teamId };
  }

  @SubscribeMessage('submitFlag')
  handleFlagSubmission(
    @MessageBody() data: { teamId: string; flag: string; challengeId: string; username: string },
    @ConnectedSocket() client: Socket,
  ) {
    const flags = this.teamFlags.get(data.teamId) || [];
    if (!flags.includes(data.flag)) {
        flags.push(data.flag);
        this.teamFlags.set(data.teamId, flags);
        
        // Broadcast success to team
        this.server.to(data.teamId).emit('flagCaptured', {
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
    @ConnectedSocket() client: Socket,
  ) {
    const notes = this.teamNotes.get(data.teamId) || [];
    const newNote = { id: Date.now().toString(), text: data.note, author: data.username, time: new Date() };
    
    notes.push(newNote);
    this.teamNotes.set(data.teamId, notes);
    
    this.server.to(data.teamId).emit('noteAdded', newNote);
  }
}
