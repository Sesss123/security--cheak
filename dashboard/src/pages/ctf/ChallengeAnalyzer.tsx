import { Lightbulb, Code, BookOpen } from 'lucide-react';

export function ChallengeAnalyzer() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500">
          <Lightbulb className="h-5 w-5 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900">CTF Challenge Analyzer</h1>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold">Challenge Details</h2>
          <textarea 
            placeholder="Paste challenge description, source code, or error logs here..." 
            className="w-full h-48 rounded-lg border border-gray-300 p-4 font-mono text-sm resize-none mb-4"
          ></textarea>
          <button className="w-full rounded-lg bg-amber-500 px-4 py-3 text-white font-semibold hover:bg-amber-600 transition-colors">
            Analyze with AI
          </button>
        </div>
        
        <div className="space-y-6">
          <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
             <h3 className="mb-3 text-md font-semibold flex items-center gap-2"><Code className="h-4 w-4" /> Categorization & Hints</h3>
             <div className="h-24 rounded bg-gray-50 border border-gray-100 flex items-center justify-center text-gray-400">
               Awaiting input...
             </div>
          </div>
          <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
             <h3 className="mb-3 text-md font-semibold flex items-center gap-2"><BookOpen className="h-4 w-4" /> Learning Path</h3>
             <div className="h-24 rounded bg-gray-50 border border-gray-100 flex items-center justify-center text-gray-400">
               Awaiting input...
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}
