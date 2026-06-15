import { Crosshair, FileSearch, Clock } from 'lucide-react';

export function ForensicsWorkbench() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-600">
          <Crosshair className="h-5 w-5 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900">Forensics Workbench</h1>
      </div>

      <div className="rounded-xl border border-dashed border-gray-300 bg-gray-50 p-12 text-center">
        <FileSearch className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900">Upload Evidence File</h3>
        <p className="text-gray-500 mb-4">Supports PCAP, Mem Dumps, Images, and Archives</p>
        <button className="rounded-lg bg-purple-600 px-6 py-2 text-white font-medium hover:bg-purple-700">Select File</button>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold">Extracted IOCs & Metadata</h2>
          <div className="h-48 rounded bg-gray-50 border border-gray-100 flex items-center justify-center text-gray-400">
            No active evidence
          </div>
        </div>
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Clock className="h-5 w-5" /> Timeline Correlation</h2>
          <div className="h-48 rounded bg-gray-50 border border-gray-100 flex items-center justify-center text-gray-400">
            No active evidence
          </div>
        </div>
      </div>
    </div>
  );
}
