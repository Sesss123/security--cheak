import { Router, Request, Response } from 'express';
import { WebSocket } from 'ws';
import { z } from 'zod';
import { db } from '../db/pool';
import { authenticate } from '../middleware/auth';
import { createScan, runScan } from '../services/scanner.service';
import { wsManager } from '../services/websocket.service';
import { chatAboutScan } from '../services/ai.service';

export const scanRouter = Router();

const CreateScanSchema = z.object({
  target_url: z.string().url(),
  scan_types: z.array(z.string()).min(1),
  options: z.object({
    rate_limit: z.number().min(1).max(50).default(10),
    timeout_secs: z.number().min(5).max(120).default(30),
    port_range: z.enum(['Common', 'Extended', 'Full']).default('Common'),
    follow_redirects: z.boolean().default(true),
    max_depth: z.number().min(1).max(10).default(3),
  }).optional(),
});

// POST /api/scans — create and start a scan
scanRouter.post('/', authenticate, async (req: Request, res: Response) => {
  try {
    const body = CreateScanSchema.parse(req.body);
    const scan = await createScan(req.user!.userId, body as any);

    // Run scan async (don't await)
    runScan(scan.id).catch(console.error);

    return res.status(202).json(scan);
  } catch (err: any) {
    if (err.name === 'ZodError') return res.status(400).json({ error: err.errors });
    return res.status(500).json({ error: 'Failed to create scan' });
  }
});

// GET /api/scans — list user's scans
scanRouter.get('/', authenticate, async (req: Request, res: Response) => {
  const page  = parseInt(req.query.page  as string) || 1;
  const limit = parseInt(req.query.limit as string) || 20;
  const offset = (page - 1) * limit;

  const result = await db.query(
    `SELECT id, target_url, status, risk_score, total_vulns,
            critical_count, high_count, medium_count, low_count,
            started_at, completed_at, created_at
     FROM scans
     WHERE user_id=$1
     ORDER BY created_at DESC
     LIMIT $2 OFFSET $3`,
    [req.user!.userId, limit, offset]
  );

  const count = await db.query(
    'SELECT COUNT(*) FROM scans WHERE user_id=$1',
    [req.user!.userId]
  );

  return res.json({
    scans: result.rows,
    total: parseInt(count.rows[0].count),
    page,
    limit,
  });
});

// GET /api/scans/:id — get scan details
scanRouter.get('/:id', authenticate, async (req: Request, res: Response) => {
  const result = await db.query(
    'SELECT * FROM scans WHERE id=$1 AND user_id=$2',
    [req.params.id, req.user!.userId]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  return res.json(result.rows[0]);
});

// GET /api/scans/:id/vulnerabilities — get all vulns for a scan
scanRouter.get('/:id/vulnerabilities', authenticate, async (req: Request, res: Response) => {
  const page  = parseInt(req.query.page as string) || 1;
  const limit = parseInt(req.query.limit as string) || 50;
  const offset = (page - 1) * limit;
  // Verify ownership
  const scan = await db.query(
    'SELECT id FROM scans WHERE id=$1 AND user_id=$2',
    [req.params.id, req.user!.userId]
  );
  if (scan.rows.length === 0) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  const severity = req.query.severity as string;
  const conditions = ['scan_id=$1'];
  const params: any[] = [req.params.id];

  if (severity) {
    conditions.push(`severity=$${params.length + 1}`);
    params.push(severity.toUpperCase());
  }

  const result = await db.query(
    `SELECT * FROM vulnerabilities
     WHERE ${conditions.join(' AND ')}
     ORDER BY cvss_score DESC, severity
     LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, limit, offset]
  );

  const count = await db.query(
    `SELECT COUNT(*) FROM vulnerabilities WHERE ${conditions.join(' AND ')}`,
    params
  );

  return res.json({
    vulnerabilities: result.rows,
    total: parseInt(count.rows[0].count),
    page,
    limit
  });
});

// GET /api/scans/:id/report — get AI report for a scan
scanRouter.get('/:id/report', authenticate, async (req: Request, res: Response) => {
  const scan = await db.query(
    'SELECT id FROM scans WHERE id=$1 AND user_id=$2',
    [req.params.id, req.user!.userId]
  );
  if (scan.rows.length === 0) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  const report = await db.query(
    'SELECT * FROM reports WHERE scan_id=$1 ORDER BY generated_at DESC LIMIT 1',
    [req.params.id]
  );

  if (report.rows.length === 0) {
    return res.status(404).json({ error: 'Report not ready yet' });
  }

  return res.json(report.rows[0]);
});

// POST /api/scans/:id/chat — AI chat about scan results
scanRouter.post('/:id/chat', authenticate, async (req: Request, res: Response) => {
  const { message, history = [] } = req.body;

  if (!message) return res.status(400).json({ error: 'message required' });

  const scan = await db.query(
    'SELECT id FROM scans WHERE id=$1 AND user_id=$2',
    [req.params.id, req.user!.userId]
  );
  if (scan.rows.length === 0) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  const vulns = await db.query(
    'SELECT title, severity, category FROM vulnerabilities WHERE scan_id=$1',
    [req.params.id]
  );

  const reply = await chatAboutScan(
    req.params.id,
    vulns.rows,
    message,
    history
  );

  return res.json({ reply });
});

// DELETE /api/scans/:id — delete a scan
scanRouter.delete('/:id', authenticate, async (req: Request, res: Response) => {
  const result = await db.query(
    'DELETE FROM scans WHERE id=$1 AND user_id=$2 RETURNING id',
    [req.params.id, req.user!.userId]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Scan not found' });
  }

  return res.json({ deleted: true });
});

// WS /api/scans/:id/live — WebSocket for live scan progress
export function handleScanWebSocket(ws: WebSocket, scanId: string): void {
  wsManager.join(scanId, ws);

  ws.send(JSON.stringify({
    type: 'connected',
    scan_id: scanId,
    message: 'Connected to scan live feed',
    timestamp: new Date().toISOString(),
  }));

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', timestamp: new Date().toISOString() }));
      }
    } catch {}
  });
}
