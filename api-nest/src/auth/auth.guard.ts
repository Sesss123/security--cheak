import { Injectable, CanActivate, ExecutionContext, Inject } from '@nestjs/common';
import { DB_POOL } from '../db/database.module';
import { Pool } from 'pg';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(@Inject(DB_POOL) private db: Pool) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    
    try {
      // Auto-login as default local user (Bypass JWT for single-user mode)
      let userResult = await this.db.query('SELECT id, email FROM users LIMIT 1');
      
      if (userResult.rows.length === 0) {
        // Create a default user if none exists
        userResult = await this.db.query(`
          INSERT INTO users (email, password_hash, name) 
          VALUES ('admin@localhost', 'dummy', 'Local Administrator') 
          RETURNING id, email
        `);
      }
      
      request.user = { userId: userResult.rows[0].id, email: userResult.rows[0].email };
      return true;
    } catch (err) {
      console.error('AuthGuard bypass error:', err);
      return false;
    }
  }
}
