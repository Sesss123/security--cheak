import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Globe, Zap, AlertCircle } from 'lucide-react';
import { scansApi } from '../services/api';
import toast from 'react-hot-toast';

const SCAN_MODULES = [
  { id: 'port_scan',        label: 'Port Scan',          desc: 'Detect open ports and services',       icon: '🔌' },
  { id: 'ssl_analysis',     label: 'SSL/TLS Analysis',   desc: 'Certificate and cipher analysis',      icon: '🔒' },
  { id: 'security_headers', label: 'Security Headers',   desc: 'Check 9 critical HTTP headers',        icon: '🛡️' },
  { id: 'sql_injection',    label: 'SQL Injection',      desc: 'Detect SQLi vulnerabilities',          icon: '💉' },
  { id: 'xss',              label: 'XSS Detection',      desc: 'Cross-site scripting checks',          icon: '⚡' },
  { id: 'cors_check',       label: 'CORS Analysis',      desc: 'Cross-origin misconfiguration',        icon: '🌐' },
  { id: 'info_disclosure',  label: 'Info Disclosure',    desc: 'Exposed .env, .git, backups',          icon: '📂' },
  { id: 'jwt_analysis',     label: 'JWT Weaknesses',     desc: 'alg=none, weak secrets',               icon: '🔑' },
  { id: 'open_redirect',    label: 'Open Redirect',      desc: 'Unvalidated redirect endpoints',       icon: '↪️' },
  { id: 'ctf_scan',         label: 'CTF Analyzer',       desc: 'Flags, subdomains, hidden paths',      icon: '🚩' },
];

export function NewScanPage() {
  const navigate = useNavigate();
  const [url, setUrl]           = useState('');
  const [modules, setModules]   = useState<string[]>(['security_headers', 'ssl_analysis', 'info_disclosure']);
  const [portRange, setPortRange] = useState('Common');
  const [rateLimit, setRateLimit] = useState(10);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');

  const toggleModule = (id: string) => {
    setModules((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]
    );
  };

  const selectAll = () => setModules(SCAN_MODULES.map((m) => m.id));
  const clearAll  = () => setModules([]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!url) return setError('Target URL is required');
    if (modules.length === 0) return setError('Select at least one scan module');

    try {
      setLoading(true);
      const scan = await scansApi.create({
        target_url: url,
        scan_types: modules,
        options: {
          port_range: portRange,
          rate_limit: rateLimit,
        },
      });
      toast.success('Scan started!');
      navigate(`/scans/${scan.id}`);
    } catch (err: any) {
      setError(err.response?.data?.error ?? 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-2xl p-6">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">New Security Scan</h1>
        <p className="text-sm text-gray-500">Configure and launch an AI-powered security assessment</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target URL */}
        <div className="rounded-xl border border-gray-200 bg-white p-6">
          <label className="mb-1 block text-sm font-semibold text-gray-700">
            <Globe className="mr-1 inline h-4 w-4" /> Target URL
          </label>
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="mt-1 w-full rounded-lg border border-gray-300 px-4 py-2.5 text-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
          <p className="mt-1 text-xs text-gray-400">
            Only scan targets you own or have explicit permission to test.
          </p>
        </div>

        {/* Scan modules */}
        <div className="rounded-xl border border-gray-200 bg-white p-6">
          <div className="mb-3 flex items-center justify-between">
            <label className="text-sm font-semibold text-gray-700">
              <Shield className="mr-1 inline h-4 w-4" /> Scan Modules
            </label>
            <div className="flex gap-3 text-xs">
              <button type="button" onClick={selectAll} className="text-indigo-600 hover:underline">
                Select all
              </button>
              <button type="button" onClick={clearAll} className="text-gray-500 hover:underline">
                Clear
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {SCAN_MODULES.map((m) => (
              <label
                key={m.id}
                className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ${
                  modules.includes(m.id)
                    ? 'border-indigo-300 bg-indigo-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <input
                  type="checkbox"
                  checked={modules.includes(m.id)}
                  onChange={() => toggleModule(m.id)}
                  className="mt-0.5 accent-indigo-600"
                />
                <div>
                  <div className="text-sm font-medium text-gray-800">
                    {m.icon} {m.label}
                  </div>
                  <div className="text-xs text-gray-500">{m.desc}</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Options */}
        <div className="rounded-xl border border-gray-200 bg-white p-6">
          <label className="mb-3 block text-sm font-semibold text-gray-700">
            <Zap className="mr-1 inline h-4 w-4" /> Scan Options
          </label>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600">Port Range</label>
              <select
                value={portRange}
                onChange={(e) => setPortRange(e.target.value)}
                className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-indigo-500 focus:outline-none"
              >
                <option value="Common">Common (Top 100)</option>
                <option value="Extended">Extended (Top 1024)</option>
                <option value="Full">Full (All 65535)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-600">
                Rate Limit (req/s): {rateLimit}
              </label>
              <input
                type="range"
                min={1} max={50}
                value={rateLimit}
                onChange={(e) => setRateLimit(parseInt(e.target.value))}
                className="mt-2 w-full accent-indigo-600"
              />
            </div>
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-lg bg-indigo-600 py-3 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-60"
        >
          {loading ? '🚀 Starting Scan...' : '🔍 Start Security Scan'}
        </button>
      </form>
    </div>
  );
}
