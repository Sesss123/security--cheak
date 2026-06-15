import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import WebSocket from 'ws';
import { rateLimit } from 'express-rate-limit';
import { checkDb } from './db/pool';
import { authRouter } from './routes/auth.routes';
import { scanRouter, handleScanWebSocket } from './routes/scan.routes';
import { analyticsRouter } from './routes/analytics.routes';

const app  = express();
const server = createServer(app);
const wss  = new WebSocket.Server({ server, path: '/ws' });

// ── Middleware ────────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(',') ?? ['http://localhost:5173'] }));
app.use(express.json({ limit: '10mb' }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 200,
  message: { error: 'Too many requests' },
}));

// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth',      authRouter);
app.use('/api/scans',     scanRouter);
app.use('/api/analytics', analyticsRouter);

app.get('/api/health', (_, res) => res.json({
  status: 'ok',
  version: '1.0.0',
  timestamp: new Date().toISOString(),
}));

// 404 handler
app.use((_, res) => res.status(404).json({ error: 'Not found' }));

// ── WebSocket ─────────────────────────────────────────────────
wss.on('connection', (ws: any, req: any) => {
  const url    = new URL(req.url!, `http://${req.headers.host}`);
  const scanId = url.searchParams.get('scanId');

  if (!scanId) {
    ws.close(1008, 'scanId required');
    return;
  }

  console.log(`WS connected for scan: ${scanId}`);
  handleScanWebSocket(ws, scanId);
});

// ── Start ─────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT ?? '3001');

async function start() {
  if (!process.env.JWT_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET environment variable is missing.');
    process.exit(1);
  }

  await checkDb();

  server.listen(PORT, () => {
    console.log(`\n🚀 Security Platform API`);
    console.log(`   REST : http://localhost:${PORT}/api`);
    console.log(`   WS   : ws://localhost:${PORT}/ws\n`);
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
