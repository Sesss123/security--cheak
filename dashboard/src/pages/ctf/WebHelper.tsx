import { Server, Key, Hash } from 'lucide-react';

export function WebHelper() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-600">
          <Server className="h-5 w-5 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900">Web Challenge Helper</h1>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Key className="h-5 w-5" /> JWT Inspector</h2>
          <textarea placeholder="Paste JWT token..." className="w-full h-32 rounded-lg border border-gray-300 p-3 text-sm mb-3"></textarea>
          <button className="w-full rounded-lg bg-emerald-600 py-2 text-white font-medium hover:bg-emerald-700">Decode JWT</button>
        </div>

        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Server className="h-5 w-5" /> Cookie Decoder</h2>
          <textarea placeholder="Paste Cookie string..." className="w-full h-32 rounded-lg border border-gray-300 p-3 text-sm mb-3"></textarea>
          <button className="w-full rounded-lg bg-emerald-600 py-2 text-white font-medium hover:bg-emerald-700">Analyze Cookies</button>
        </div>

        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Hash className="h-5 w-5" /> Base64 / URL Decoder</h2>
          <textarea placeholder="Paste encoded string..." className="w-full h-32 rounded-lg border border-gray-300 p-3 text-sm mb-3"></textarea>
          <button className="w-full rounded-lg bg-emerald-600 py-2 text-white font-medium hover:bg-emerald-700">Auto-Decode</button>
        </div>
      </div>
    </div>
  );
}
