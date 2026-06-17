import { useState } from 'react';
import { Lightbulb, Code, BookOpen, AlertTriangle, Bug, Zap, Shield, HelpCircle, XCircle, Search } from 'lucide-react';
import { ctfService } from '../../services/ctf.service';

export function ChallengeAnalyzer() {
  const [code, setCode] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<any>(null);

  const handleAnalyze = async () => {
    if (!code.trim()) return;
    setIsAnalyzing(true);
    try {
      const data = await ctfService.analyzeCode(code);
      setResults(data);
    } catch (error) {
      console.error('Failed to analyze code:', error);
      alert('Failed to connect to the analysis service.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const renderList = (items: string[], emptyText: string) => {
    if (!items || items.length === 0) return <p className="text-gray-500 italic text-sm">{emptyText}</p>;
    return (
      <ul className="list-disc pl-5 space-y-1 text-sm text-gray-700">
        {items.map((item, idx) => (
          <li key={idx}>{item}</li>
        ))}
      </ul>
    );
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500">
          <Lightbulb className="h-5 w-5 text-white" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900">Advanced Code Analyzer</h1>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm h-fit">
          <h2 className="mb-4 text-lg font-semibold flex items-center gap-2">
            <Code className="h-5 w-5 text-amber-500" /> Source Code Snippet
          </h2>
          <textarea 
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste CTF challenge source code (PHP, Python, JS, etc.) here for deep AI analysis..." 
            className="w-full h-96 rounded-lg border border-gray-300 p-4 font-mono text-sm resize-y mb-4 focus:ring-amber-500 focus:border-amber-500"
          ></textarea>
          <button 
            onClick={handleAnalyze}
            disabled={isAnalyzing || !code.trim()}
            className="w-full rounded-lg bg-amber-500 px-4 py-3 text-white font-semibold hover:bg-amber-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center gap-2"
          >
            {isAnalyzing ? (
              <><Search className="h-5 w-5 animate-pulse" /> Analyzing Code...</>
            ) : (
              <><Search className="h-5 w-5" /> Analyze with AI</>
            )}
          </button>
        </div>
        
        <div className="space-y-6">
          {results ? (
            <div className="grid gap-4">
              <div className="rounded-xl border border-blue-200 bg-blue-50/50 p-5 shadow-sm">
                 <h3 className="mb-3 text-md font-bold text-blue-800 flex items-center gap-2"><Bug className="h-4 w-4" /> Bugs & Defects</h3>
                 {renderList(results.bugs, "No obvious bugs detected.")}
              </div>

              <div className="rounded-xl border border-red-200 bg-red-50/50 p-5 shadow-sm">
                 <h3 className="mb-3 text-md font-bold text-red-800 flex items-center gap-2"><Shield className="h-4 w-4" /> Security Issues</h3>
                 {renderList(results.securityIssues, "No immediate security vulnerabilities found.")}
              </div>

              <div className="rounded-xl border border-orange-200 bg-orange-50/50 p-5 shadow-sm">
                 <h3 className="mb-3 text-md font-bold text-orange-800 flex items-center gap-2"><AlertTriangle className="h-4 w-4" /> Logic Flaws</h3>
                 {renderList(results.logicFlaws, "No business logic flaws detected.")}
              </div>

              <div className="rounded-xl border border-purple-200 bg-purple-50/50 p-5 shadow-sm">
                 <h3 className="mb-3 text-md font-bold text-purple-800 flex items-center gap-2"><Zap className="h-4 w-4" /> Performance Issues</h3>
                 {renderList(results.performanceIssues, "Code appears performant.")}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
                   <h3 className="mb-3 text-sm font-bold text-gray-700 flex items-center gap-2"><Code className="h-4 w-4 text-gray-500" /> Code Quality</h3>
                   {renderList(results.codeQuality, "Code is perfectly clean.")}
                </div>
                <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
                   <h3 className="mb-3 text-sm font-bold text-gray-700 flex items-center gap-2"><BookOpen className="h-4 w-4 text-gray-500" /> Architecture</h3>
                   {renderList(results.architectureProblems, "Sound architecture.")}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-xl border border-green-200 bg-green-50 p-5 shadow-sm">
                   <h3 className="mb-3 text-sm font-bold text-green-800 flex items-center gap-2"><HelpCircle className="h-4 w-4" /> False Positives</h3>
                   {renderList(results.falsePositives, "None identified.")}
                </div>
                <div className="rounded-xl border border-gray-200 bg-gray-50 p-5 shadow-sm">
                   <h3 className="mb-3 text-sm font-bold text-gray-800 flex items-center gap-2"><XCircle className="h-4 w-4" /> False Negatives</h3>
                   {renderList(results.falseNegatives, "None identified.")}
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border-2 border-dashed border-gray-200 bg-white p-12 text-center text-gray-500 flex flex-col items-center justify-center h-full min-h-[400px]">
              <Search className="h-12 w-12 text-gray-300 mb-4" />
              <p className="text-lg font-medium text-gray-900">No Analysis Results</p>
              <p className="mt-2">Paste code and click Analyze to see the AI breakdown across 8 categories.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
