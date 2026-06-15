import { useState, useEffect } from 'react';
import axios from 'axios';
import { Server, Cpu } from 'lucide-react';

interface HealthResponse {
  api: string;
  worker: string;
  activeWorkers: number;
}

export function SystemStatus() {
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await axios.get('http://localhost:3001/api/health', {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        setHealth(res.data);
      } catch (error) {
        setHealth({ api: 'offline', worker: 'offline', activeWorkers: 0 });
      }
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 10000); // Check every 10 seconds
    return () => clearInterval(interval);
  }, []);

  if (!health) {
    return null;
  }

  const isApiOnline = health.api === 'online';
  const isWorkerOnline = health.worker === 'online';

  return (
    <div className="flex flex-col gap-2 rounded-lg bg-gray-50 p-4 border border-gray-100">
      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">System Status</h3>
      
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2 text-gray-700">
          <Server className="h-4 w-4" />
          <span>API Server</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-medium text-gray-500">
            {isApiOnline ? 'Online' : 'Offline'}
          </span>
          <span className={`relative flex h-2.5 w-2.5`}>
            {isApiOnline && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
            <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${isApiOnline ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
          </span>
        </div>
      </div>

      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2 text-gray-700">
          <Cpu className="h-4 w-4" />
          <span>Worker Node</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-medium text-gray-500">
            {isWorkerOnline ? `${health.activeWorkers} Active` : 'Offline'}
          </span>
          <span className={`relative flex h-2.5 w-2.5`}>
            {isWorkerOnline && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
            <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${isWorkerOnline ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
          </span>
        </div>
      </div>
    </div>
  );
}
