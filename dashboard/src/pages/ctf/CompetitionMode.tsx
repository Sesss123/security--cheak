import { Shield, Flag, Users, MessageSquare } from 'lucide-react';

export function CompetitionMode() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-orange-600">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900">Competition Dashboard</h1>
        </div>
        <div className="flex items-center gap-2 bg-white px-4 py-2 rounded-lg border border-gray-200 shadow-sm">
          <span className="text-sm font-medium text-gray-500">Team Score:</span>
          <span className="text-xl font-bold text-orange-600">0</span>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Flag className="h-5 w-5" /> Submit Flag</h2>
            <div className="flex gap-2">
              <input type="text" placeholder="flag{...}" className="flex-1 rounded-lg border border-gray-300 px-4 py-3 font-mono" />
              <button className="rounded-lg bg-orange-600 px-6 py-3 text-white font-bold hover:bg-orange-700">Submit</button>
            </div>
          </div>

          <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm min-h-[300px]">
            <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Users className="h-5 w-5" /> Evidence Board & Challenges</h2>
            <div className="flex items-center justify-center h-full text-gray-400">
              No active challenges tracked
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-gray-200 bg-white flex flex-col shadow-sm h-[500px]">
          <div className="p-4 border-b border-gray-100">
            <h2 className="text-lg font-semibold flex items-center gap-2"><MessageSquare className="h-5 w-5" /> Team Comms</h2>
          </div>
          <div className="flex-1 bg-gray-50 p-4 overflow-y-auto flex items-center justify-center text-gray-400 text-sm">
            No messages yet.
          </div>
          <div className="p-4 border-t border-gray-100">
            <div className="flex gap-2">
              <input type="text" placeholder="Send team message..." className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm" />
              <button className="rounded-lg bg-gray-900 px-4 py-2 text-white text-sm font-medium hover:bg-gray-800">Send</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
