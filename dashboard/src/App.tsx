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

// CTF & Recon Pages
import { CtfHubPage }         from './pages/ctf/CtfHubPage';
import { ReconDashboard }     from './pages/ctf/ReconDashboard';
import { ChallengeAnalyzer }  from './pages/ctf/ChallengeAnalyzer';
import { WebHelper }          from './pages/ctf/WebHelper';
import { ForensicsWorkbench } from './pages/ctf/ForensicsWorkbench';
import { CryptoToolkit }      from './pages/ctf/CryptoToolkit';
import { ReverseEngineering } from './pages/ctf/ReverseEngineering';
import { CompetitionMode }    from './pages/ctf/CompetitionMode';

const qc = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, retry: 1 },
  },
});

function PrivateRoute({ children }: { children: React.ReactNode }) {
  // Login bypassed for local single-user mode
  return <>{children}</>;
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
            
            {/* CTF & Recon Pages */}
            <Route path="/ctf"                     element={<CtfHubPage />} />
            <Route path="/ctf/recon"               element={<ReconDashboard />} />
            <Route path="/ctf/challenge-analyzer"  element={<ChallengeAnalyzer />} />
            <Route path="/ctf/web-helper"          element={<WebHelper />} />
            <Route path="/ctf/forensics"           element={<ForensicsWorkbench />} />
            <Route path="/ctf/crypto"              element={<CryptoToolkit />} />
            <Route path="/ctf/re"                  element={<ReverseEngineering />} />
            <Route path="/ctf/competition"         element={<CompetitionMode />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
      <Toaster position="top-right" />
    </QueryClientProvider>
  );
}
