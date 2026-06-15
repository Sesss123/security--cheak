import { NavLink, Outlet } from 'react-router-dom';
import {
  Shield, LayoutDashboard, Scan, BarChart2, LogOut, User,
  Crosshair, Search, Lightbulb, Server, Lock, Cpu, Trophy
} from 'lucide-react';
import { useAuthStore } from '../store/auth.store';
import { clsx } from 'clsx';
import { SystemStatus } from './SystemStatus';

const NAV = [
  { to: '/',         icon: LayoutDashboard, label: 'Dashboard', exact: true },
  { to: '/scans',    icon: Scan,            label: 'Scans' },
  { to: '/analytics',icon: BarChart2,       label: 'Analytics' },
];

const CTF_NAV = [
  { to: '/ctf',                    icon: Trophy,      label: 'CTF Hub', exact: true },
  { to: '/ctf/recon',              icon: Search,      label: 'Smart Recon' },
  { to: '/ctf/challenge-analyzer', icon: Lightbulb,   label: 'Analyzer' },
  { to: '/ctf/web-helper',         icon: Server,      label: 'Web Helper' },
  { to: '/ctf/forensics',          icon: Crosshair,   label: 'Forensics' },
  { to: '/ctf/crypto',             icon: Lock,        label: 'Crypto' },
  { to: '/ctf/re',                 icon: Cpu,         label: 'Rev-Eng' },
  { to: '/ctf/competition',        icon: Shield,      label: 'Competition' },
];

export function Layout() {
  const { user, logout } = useAuthStore();

  return (
    <div className="flex min-h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="flex w-56 flex-col border-r border-gray-200 bg-white">
        {/* Logo */}
        <div className="flex items-center gap-2.5 border-b border-gray-100 px-5 py-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600">
            <Shield className="h-4 w-4 text-white" />
          </div>
          <span className="text-sm font-bold text-gray-900">SecureScan</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 space-y-0.5 p-3">
          {NAV.map(({ to, icon: Icon, label, exact }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-indigo-50 text-indigo-700'
                    : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}

          <div className="pt-4 pb-1">
            <p className="px-3 text-xs font-semibold uppercase tracking-wider text-gray-500">
              CTF Assistant
            </p>
          </div>
          {CTF_NAV.map(({ to, icon: Icon, label, exact }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-indigo-50 text-indigo-700'
                    : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* System Status */}
        <div className="p-3">
          <SystemStatus />
        </div>

        {/* User */}
        <div className="border-t border-gray-100 p-3">
          <div className="flex items-center gap-2.5 rounded-lg px-3 py-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-indigo-100">
              <User className="h-3.5 w-3.5 text-indigo-600" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-semibold text-gray-900">{user?.name || 'Local Administrator'}</p>
              <p className="truncate text-xs text-gray-400">{user?.email || 'admin@localhost'}</p>
            </div>
            <button onClick={logout} className="text-gray-400 hover:text-red-500">
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
