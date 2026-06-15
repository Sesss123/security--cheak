import { Cpu, Terminal, FileCode2 } from 'lucide-react';

export function ReverseEngineering() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-teal-600">
          <Cpu className="h-5 w-5 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900">Reverse Engineering Assistant</h1>
      </div>

      <div className="rounded-xl border border-dashed border-gray-300 bg-gray-50 p-12 text-center">
        <FileCode2 className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900">Upload Executable (ELF/PE/Mach-O)</h3>
        <p className="text-gray-500 mb-4">Max file size: 50MB</p>
        <button className="rounded-lg bg-teal-600 px-6 py-2 text-white font-medium hover:bg-teal-700">Select Binary</button>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Terminal className="h-5 w-5" /> Strings & Imports Analysis</h2>
          <div className="h-48 rounded bg-gray-50 border border-gray-100 flex items-center justify-center text-gray-400">
            No binary loaded
          </div>
        </div>
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Cpu className="h-5 w-5" /> AI Binary Summary</h2>
          <div className="h-48 rounded bg-gray-50 border border-gray-100 flex items-center justify-center text-gray-400">
            No binary loaded
          </div>
        </div>
      </div>
    </div>
  );
}
