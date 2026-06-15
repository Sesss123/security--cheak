import { useQuery } from '@tanstack/react-query';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid, Legend,
} from 'recharts';
import { analyticsApi } from '../services/api';

const OWASP_COLORS = [
  '#6366f1','#8b5cf6','#ec4899','#ef4444',
  '#f97316','#eab308','#22c55e','#14b8a6','#3b82f6','#64748b',
];

export function AnalyticsPage() {
  const { data: vuln } = useQuery({
    queryKey: ['analytics', 'vulnerabilities'],
    queryFn: analyticsApi.vulnerabilities,
  });

  return (
    <div className="space-y-8 p-6">
      <h1 className="text-2xl font-bold text-gray-900">Analytics</h1>

      {/* Vulnerability categories */}
      {vuln?.by_category?.length > 0 && (
        <div className="rounded-xl border border-gray-200 bg-white p-6">
          <h2 className="mb-4 text-sm font-semibold text-gray-700">Top Vulnerability Categories</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={vuln.by_category} layout="vertical" margin={{ left: 120 }}>
              <XAxis type="number" tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="category" tick={{ fontSize: 11 }} width={120} />
              <Tooltip />
              <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* OWASP breakdown */}
      {vuln?.by_owasp?.length > 0 && (
        <div className="rounded-xl border border-gray-200 bg-white p-6">
          <h2 className="mb-4 text-sm font-semibold text-gray-700">OWASP Top 10 Breakdown</h2>
          <div className="space-y-3">
            {vuln.by_owasp.map((item: any, i: number) => {
              const max = Math.max(...vuln.by_owasp.map((v: any) => parseInt(v.count)));
              const pct = (parseInt(item.count) / max) * 100;
              return (
                <div key={item.owasp_category} className="flex items-center gap-3">
                  <div className="w-52 truncate text-xs text-gray-600">{item.owasp_category}</div>
                  <div className="flex-1 rounded-full bg-gray-100 h-2">
                    <div
                      className="h-2 rounded-full"
                      style={{ width: `${pct}%`, backgroundColor: OWASP_COLORS[i % OWASP_COLORS.length] }}
                    />
                  </div>
                  <span className="w-8 text-right text-xs font-semibold text-gray-700">{item.count}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 30-day trend */}
      {vuln?.trend_30_days?.length > 0 && (
        <div className="rounded-xl border border-gray-200 bg-white p-6">
          <h2 className="mb-4 text-sm font-semibold text-gray-700">30-Day Vulnerability Trend</h2>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={vuln.trend_30_days}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis dataKey="date" tick={{ fontSize: 10 }} />
              <YAxis tick={{ fontSize: 10 }} />
              <Tooltip />
              <Legend />
              <Line
                type="monotone"
                dataKey="total_vulns"
                stroke="#6366f1"
                strokeWidth={2}
                dot={false}
                name="Vulnerabilities"
              />
              <Line
                type="monotone"
                dataKey="avg_risk"
                stroke="#f97316"
                strokeWidth={2}
                dot={false}
                name="Avg Risk Score"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {(!vuln?.by_category?.length && !vuln?.trend_30_days?.length) && (
        <div className="rounded-xl border border-gray-200 bg-white p-12 text-center text-gray-400">
          <p className="text-lg">📊</p>
          <p className="mt-2 text-sm">No analytics yet. Run some scans to see data here.</p>
        </div>
      )}
    </div>
  );
}
