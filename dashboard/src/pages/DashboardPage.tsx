import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line,
} from 'recharts';
import { Shield, AlertTriangle, CheckCircle, Scan, Plus } from 'lucide-react';
import { analyticsApi, scansApi } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScore } from '../components/RiskScore';
import { formatDistanceToNow } from 'date-fns';

const PIE_COLORS = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
  INFO:     '#3b82f6',
};

export function DashboardPage() {
  const { data: overview } = useQuery({
    queryKey: ['analytics', 'overview'],
    queryFn: analyticsApi.overview,
  });

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list(1),
  });

  const recentScans = scansData?.scans?.slice(0, 5) ?? [];

  return (
    <div className="space-y-8 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-sm text-gray-500">AI-Powered Security Assessment Platform</p>
        </div>
        <Link
          to="/scans/new"
          className="flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </Link>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={<Scan className="h-5 w-5 text-indigo-600" />}
          label="Total Scans"
          value={overview?.total_scans ?? 0}
          bg="bg-indigo-50"
        />
        <StatCard
          icon={<AlertTriangle className="h-5 w-5 text-red-600" />}
          label="Critical Issues"
          value={overview?.vulnerability_breakdown?.find((v: any) => v.severity === 'CRITICAL')?.count ?? 0}
          bg="bg-red-50"
        />
        <StatCard
          icon={<Shield className="h-5 w-5 text-orange-600" />}
          label="High Issues"
          value={overview?.vulnerability_breakdown?.find((v: any) => v.severity === 'HIGH')?.count ?? 0}
          bg="bg-orange-50"
        />
        <StatCard
          icon={<CheckCircle className="h-5 w-5 text-green-600" />}
          label="Completed Scans"
          value={recentScans.filter((s: any) => s.status === 'completed').length}
          bg="bg-green-50"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Vulnerability breakdown pie */}
        {overview?.vulnerability_breakdown?.length > 0 && (
          <div className="rounded-xl border border-gray-200 bg-white p-6">
            <h2 className="mb-4 text-sm font-semibold text-gray-700">Vulnerability Breakdown</h2>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={overview.vulnerability_breakdown}
                  dataKey="count"
                  nameKey="severity"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  label={({ severity, count }) => `${severity}: ${count}`}
                >
                  {overview.vulnerability_breakdown.map((entry: any) => (
                    <Cell
                      key={entry.severity}
                      fill={PIE_COLORS[entry.severity as keyof typeof PIE_COLORS] ?? '#94a3b8'}
                    />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Scan trend bar */}
        {overview?.scan_trend?.length > 0 && (
          <div className="rounded-xl border border-gray-200 bg-white p-6">
            <h2 className="mb-4 text-sm font-semibold text-gray-700">Scans (Last 7 Days)</h2>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={overview.scan_trend}>
                <XAxis dataKey="date" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Recent scans table */}
      <div className="rounded-xl border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-100 px-6 py-4">
          <h2 className="text-sm font-semibold text-gray-700">Recent Scans</h2>
          <Link to="/scans" className="text-xs text-indigo-600 hover:underline">View all</Link>
        </div>

        {recentScans.length === 0 ? (
          <div className="py-12 text-center text-sm text-gray-500">
            No scans yet.{' '}
            <Link to="/scans/new" className="text-indigo-600 hover:underline">Start your first scan</Link>
          </div>
        ) : (
          <div className="divide-y divide-gray-50">
            {recentScans.map((scan: any) => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                className="flex items-center gap-4 px-6 py-4 hover:bg-gray-50"
              >
                <StatusDot status={scan.status} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-gray-900">{scan.target_url}</p>
                  <p className="text-xs text-gray-500">
                    {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                  </p>
                </div>
                {scan.risk_score != null && (
                  <RiskScore score={parseFloat(scan.risk_score)} size="sm" />
                )}
                <div className="text-right text-xs text-gray-500">
                  <div className="font-semibold text-gray-800">{scan.total_vulns ?? 0}</div>
                  <div>vulns</div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ icon, label, value, bg }: {
  icon: React.ReactNode; label: string; value: number; bg: string;
}) {
  return (
    <div className="flex items-center gap-4 rounded-xl border border-gray-200 bg-white p-5">
      <div className={`rounded-lg p-2 ${bg}`}>{icon}</div>
      <div>
        <p className="text-xs text-gray-500">{label}</p>
        <p className="text-2xl font-bold text-gray-900">{value}</p>
      </div>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    completed: 'bg-green-500',
    running:   'bg-blue-500 animate-pulse',
    pending:   'bg-yellow-400',
    failed:    'bg-red-500',
  };
  return (
    <span className={`h-2.5 w-2.5 flex-shrink-0 rounded-full ${colors[status] ?? 'bg-gray-300'}`} />
  );
}
