import { Search, Globe, ShieldAlert } from 'lucide-react';

export function ReconDashboard() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-600">
          <Search className="h-5 w-5 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900">Smart Recon</h1>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Globe className="h-5 w-5 text-blue-500" /> Target Discovery</h2>
          <div className="flex gap-2 mb-4">
            <input type="text" placeholder="Enter target domain (e.g. example.com)" className="flex-1 rounded-lg border border-gray-300 px-4 py-2" />
            <button className="rounded-lg bg-blue-600 px-4 py-2 text-white font-medium hover:bg-blue-700">Scan</button>
          </div>
          <div className="h-48 rounded bg-gray-50 border border-gray-100 flex items-center justify-center text-gray-400">
            No active scans
          </div>
        </div>
        
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><ShieldAlert className="h-5 w-5 text-red-500" /> Attack Surface Map</h2>
          <div className="h-64 rounded bg-gray-50 border border-gray-100 flex items-center justify-center text-gray-400">
            Run a scan to generate map
          </div>
        </div>
      </div>
    </div>
  );
}
