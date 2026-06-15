import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Trash2, ExternalLink, Search } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { scansApi } from '../services/api';
import { RiskScore } from '../components/RiskScore';
import toast from 'react-hot-toast';

export function ScansPage() {
  const qc = useQueryClient();
  const [page, setPage]     = useState(1);
  const [search, setSearch] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['scans', page],
    queryFn: () => scansApi.list(page),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => scansApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      toast.success('Scan deleted');
    },
  });

  const scans = (data?.scans ?? []).filter((s: any) =>
    search ? s.target_url.includes(search) : true
  );

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Scans</h1>
        <Link
          to="/scans/new"
          className="flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700"
        >
          <Plus className="h-4 w-4" /> New Scan
        </Link>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by URL..."
          className="w-full rounded-lg border border-gray-200 pl-10 pr-4 py-2.5 text-sm focus:border-indigo-400 focus:outline-none"
        />
      </div>

      {/* Table */}
      <div className="rounded-xl border border-gray-200 bg-white overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-100">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Target</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
              <th className="px-4 py-3 text-center text-xs font-semibold text-gray-500 uppercase">Risk</th>
              <th className="px-4 py-3 text-center text-xs font-semibold text-gray-500 uppercase">Vulns</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Date</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {isLoading ? (
              <tr><td colSpan={6} className="py-12 text-center text-gray-400">Loading...</td></tr>
            ) : scans.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-gray-400">
                  No scans yet.{' '}
                  <Link to="/scans/new" className="text-indigo-600 hover:underline">Start one</Link>
                </td>
              </tr>
            ) : scans.map((scan: any) => (
              <tr key={scan.id} className="hover:bg-gray-50">
                <td className="px-4 py-3">
                  <Link to={`/scans/${scan.id}`} className="font-medium text-gray-900 hover:text-indigo-600 flex items-center gap-1.5">
                    <span className="truncate max-w-xs">{scan.target_url}</span>
                    <ExternalLink className="h-3 w-3 flex-shrink-0 text-gray-400" />
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={scan.status} />
                </td>
                <td className="px-4 py-3 text-center">
                  {scan.risk_score != null
                    ? <RiskScore score={parseFloat(scan.risk_score)} size="sm" />
                    : <span className="text-gray-400">—</span>}
                </td>
                <td className="px-4 py-3 text-center">
                  <div className="flex justify-center gap-1.5">
                    {scan.critical_count > 0 && (
                      <span className="rounded-full bg-red-100 px-1.5 py-0.5 text-xs font-semibold text-red-700">
                        {scan.critical_count}C
                      </span>
                    )}
                    {scan.high_count > 0 && (
                      <span className="rounded-full bg-orange-100 px-1.5 py-0.5 text-xs font-semibold text-orange-700">
                        {scan.high_count}H
                      </span>
                    )}
                    {scan.medium_count > 0 && (
                      <span className="rounded-full bg-yellow-100 px-1.5 py-0.5 text-xs font-semibold text-yellow-700">
                        {scan.medium_count}M
                      </span>
                    )}
                    {scan.total_vulns === 0 && (
                      <span className="text-gray-400 text-xs">—</span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs">
                  {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => {
                      if (confirm('Delete this scan?')) deleteMutation.mutate(scan.id);
                    }}
                    className="text-gray-400 hover:text-red-500"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        {data?.total > 20 && (
          <div className="flex items-center justify-between border-t border-gray-100 px-4 py-3">
            <span className="text-xs text-gray-500">
              {data.total} total scans
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="rounded-lg border border-gray-200 px-3 py-1.5 text-xs disabled:opacity-40"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page * 20 >= data.total}
                className="rounded-lg border border-gray-200 px-3 py-1.5 text-xs disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    pending:   { label: 'Pending',   cls: 'bg-yellow-100 text-yellow-800' },
    running:   { label: '⟳ Running', cls: 'bg-blue-100 text-blue-800' },
    completed: { label: 'Completed', cls: 'bg-green-100 text-green-800' },
    failed:    { label: 'Failed',    cls: 'bg-red-100 text-red-800' },
  };
  const { label, cls } = map[status] ?? { label: status, cls: 'bg-gray-100 text-gray-700' };
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${cls}`}>{label}</span>
  );
}
