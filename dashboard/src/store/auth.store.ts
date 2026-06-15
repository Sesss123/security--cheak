import { create } from 'zustand';
import { authApi } from '../services/api';

interface User {
  id: string;
  name: string;
  email: string;
  role: string;
}

interface AuthStore {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  loadUser: () => Promise<void>;
}

export const useAuthStore = create<AuthStore>((set) => ({
  user: null,
  token: localStorage.getItem('token'),
  loading: false,

  login: async (email, password) => {
    set({ loading: true });
    const data = await authApi.login(email, password);
    localStorage.setItem('token', data.token);
    set({ user: data.user, token: data.token, loading: false });
  },

  register: async (name, email, password) => {
    set({ loading: true });
    const data = await authApi.register(name, email, password);
    localStorage.setItem('token', data.token);
    set({ user: data.user, token: data.token, loading: false });
  },

  logout: () => {
    localStorage.removeItem('token');
    set({ user: null, token: null });
    window.location.href = '/login';
  },

  loadUser: async () => {
    if (!localStorage.getItem('token')) return;
    try {
      const user = await authApi.me();
      set({ user });
    } catch {
      localStorage.removeItem('token');
      set({ user: null, token: null });
    }
  },
}));
