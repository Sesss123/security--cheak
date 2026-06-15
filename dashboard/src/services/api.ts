import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:3001/api';
const WS_BASE  = import.meta.env.VITE_WS_URL  ?? 'ws://localhost:3001/ws';

// ── Axios instance ────────────────────────────────────────────
export const api = axios.create({ baseURL: API_BASE });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

// ── Auth ──────────────────────────────────────────────────────
export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }).then((r) => r.data),
  register: (name: string, email: string, password: string) =>
    api.post('/auth/register', { name, email, password }).then((r) => r.data),
  me: () => api.get('/auth/me').then((r) => r.data),
};

// ── Scans ─────────────────────────────────────────────────────
export const scansApi = {
  list: (page = 1) =>
    api.get(`/scans?page=${page}`).then((r) => r.data),
  get: (id: string) =>
    api.get(`/scans/${id}`).then((r) => r.data),
  create: (body: {
    target_url: string;
    scan_types: string[];
    options?: Record<string, unknown>;
  }) => api.post('/scans', body).then((r) => r.data),
  delete: (id: string) =>
    api.delete(`/scans/${id}`).then((r) => r.data),
  vulnerabilities: (id: string, severity?: string) =>
    api.get(`/scans/${id}/vulnerabilities${severity ? `?severity=${severity}` : ''}`).then((r) => r.data),
  report: (id: string) =>
    api.get(`/scans/${id}/report`).then((r) => r.data),
  chat: (id: string, message: string, history: unknown[]) =>
    api.post(`/scans/${id}/chat`, { message, history }).then((r) => r.data),
};

// ── Analytics ─────────────────────────────────────────────────
export const analyticsApi = {
  overview: () => api.get('/analytics/overview').then((r) => r.data),
  vulnerabilities: () => api.get('/analytics/vulnerabilities').then((r) => r.data),
};

// ── WebSocket ─────────────────────────────────────────────────
export function connectScanWS(
  scanId: string,
  onEvent: (event: { type: string; data: unknown }) => void
): WebSocket {
  const ws = new WebSocket(`${WS_BASE}?scanId=${scanId}`);

  ws.onmessage = (e) => {
    try { onEvent(JSON.parse(e.data)); } catch {}
  };

  ws.onerror = (e) => console.error('WS error:', e);

  // Keepalive ping
  const ping = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'ping' }));
    }
  }, 30_000);

  ws.onclose = () => clearInterval(ping);

  return ws;
}
