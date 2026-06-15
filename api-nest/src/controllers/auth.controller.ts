import { Controller, Post, Get, Body, Req, Res, HttpStatus, UseGuards, Inject } from '@nestjs/common';
import type { Request, Response } from 'express';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { z } from 'zod';
import { DB_POOL } from '../db/database.module';
import { Pool } from 'pg';
import { AuthGuard } from '../auth/auth.guard';

const RegisterSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(8),
});

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

@Controller('api/auth')
export class AuthController {
  constructor(@Inject(DB_POOL) private db: Pool) {}

  @Post('register')
  async register(@Body() bodyData: any, @Res() res: Response) {
    try {
      const body = RegisterSchema.parse(bodyData);

      const existing = await this.db.query('SELECT id FROM users WHERE email=$1', [body.email]);
      if (existing.rows.length > 0) {
        return res.status(HttpStatus.CONFLICT).json({ error: 'Email already registered' });
      }

      const hash = await bcrypt.hash(body.password, 10);
      const result = await this.db.query(
        `INSERT INTO users (name, email, password_hash) VALUES ($1,$2,$3) RETURNING id, name, email, role`,
        [body.name, body.email, hash]
      );

      const user = result.rows[0];
      const token = this.signToken(user);

      return res.status(HttpStatus.CREATED).json({ user, token });
    } catch (err: any) {
      if (err.name === 'ZodError') return res.status(HttpStatus.BAD_REQUEST).json({ error: err.errors });
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ error: 'Registration failed' });
    }
  }

  @Post('login')
  async login(@Body() bodyData: any, @Res() res: Response) {
    try {
      const body = LoginSchema.parse(bodyData);

      const result = await this.db.query('SELECT * FROM users WHERE email=$1', [body.email]);
      const user = result.rows[0];

      if (!user || !(await bcrypt.compare(body.password, user.password_hash))) {
        return res.status(HttpStatus.UNAUTHORIZED).json({ error: 'Invalid email or password' });
      }

      const token = this.signToken(user);
      return res.json({
        user: { id: user.id, name: user.name, email: user.email, role: user.role },
        token,
      });
    } catch (err: any) {
      if (err.name === 'ZodError') return res.status(HttpStatus.BAD_REQUEST).json({ error: err.errors });
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ error: 'Login failed' });
    }
  }

  @UseGuards(AuthGuard)
  @Get('me')
  async getMe(@Req() req: any, @Res() res: Response) {
    const result = await this.db.query(
      'SELECT id, name, email, role, created_at FROM users WHERE id=$1',
      [req.user.userId]
    );
    return res.json(result.rows[0]);
  }

  private signToken(user: { id: string; email: string; role: string }) {
    return jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET!,
      { expiresIn: '7d' }
    );
  }
}
