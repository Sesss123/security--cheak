import { Lock, Shuffle, KeyRound } from 'lucide-react';

export function CryptoToolkit() {
  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-pink-600">
          <Lock className="h-5 w-5 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900">Crypto Toolkit</h1>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-6">
          <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><Shuffle className="h-5 w-5" /> Cipher Identifier</h2>
            <textarea placeholder="Paste ciphertext..." className="w-full h-32 rounded-lg border border-gray-300 p-3 text-sm mb-3"></textarea>
            <button className="w-full rounded-lg bg-pink-600 py-2 text-white font-medium hover:bg-pink-700">Identify Cipher</button>
          </div>
        </div>

        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2"><KeyRound className="h-5 w-5" /> Hash Analyzer</h2>
          <input type="text" placeholder="Enter hash string..." className="w-full rounded-lg border border-gray-300 px-4 py-2 mb-4" />
          <button className="w-full rounded-lg bg-pink-600 py-2 text-white font-medium hover:bg-pink-700">Analyze Hash</button>
          
          <div className="mt-6 pt-6 border-t border-gray-100">
            <h3 className="mb-3 text-md font-medium text-gray-700">Analysis Results</h3>
            <div className="h-32 rounded bg-gray-50 border border-gray-100 flex items-center justify-center text-gray-400">
               Ready for input
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}
