import { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'react-hot-toast';
import { useAuthStore } from './store/auth.store';
import { Layout } from './components/Layout';
import { LoginPage }      from './pages/LoginPage';
import { RegisterPage }   from './pages/RegisterPage';
import { DashboardPage }  from './pages/DashboardPage';
import { ScansPage }      from './pages/ScansPage';
import { NewScanPage }    from './pages/NewScanPage';
import { ScanDetailPage } from './pages/ScanDetailPage';
import { AnalyticsPage }  from './pages/AnalyticsPage';

const qc = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, retry: 1 },
  },
});

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token);
  return token ? <>{children}</> : <Navigate to="/login" replace />;
}

export default function App() {
  const loadUser = useAuthStore((s) => s.loadUser);

  useEffect(() => { loadUser(); }, []);

  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          {/* Public */}
          <Route path="/login"    element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Private */}
          <Route element={<PrivateRoute><Layout /></PrivateRoute>}>
            <Route path="/"              element={<DashboardPage />} />
            <Route path="/scans"         element={<ScansPage />} />
            <Route path="/scans/new"     element={<NewScanPage />} />
            <Route path="/scans/:id"     element={<ScanDetailPage />} />
            <Route path="/analytics"     element={<AnalyticsPage />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
      <Toaster position="top-right" />
    </QueryClientProvider>
  );
}
