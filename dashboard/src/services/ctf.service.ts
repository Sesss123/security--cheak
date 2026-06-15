import axios from 'axios';

const API_URL = (import.meta as any).env.VITE_API_URL || 'http://localhost:3000';

const api = axios.create({
  baseURL: `${API_URL}/ctf`,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_state') ? JSON.parse(localStorage.getItem('auth_state') as string).state?.token : null;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const ctfService = {
  // Recon
  discoverSubdomains: async (domain: string) => {
    const res = await api.post('/recon/subdomains', { domain });
    return res.data;
  },

  // Knowledge Base
  queryRag: async (query: string) => {
    const res = await api.post('/rag/query', { query });
    return res.data;
  },

  // Forensics
  uploadForensics: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/forensics/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },
};
