import { Trophy, Search, Lightbulb, Server, Crosshair, Lock, Cpu, Shield } from 'lucide-react';
import { Link } from 'react-router-dom';

const modules = [
  { to: '/ctf/recon', icon: Search, title: 'Smart Recon', desc: 'DNS, Subdomains, and Attack Surface Mapping' },
  { to: '/ctf/challenge-analyzer', icon: Lightbulb, title: 'Challenge Analyzer', desc: 'AI-driven categorization and hint generation' },
  { to: '/ctf/web-helper', icon: Server, title: 'Web Helper', desc: 'Inspect HTTP, Cookies, JWTs, and encodings' },
  { to: '/ctf/forensics', icon: Crosshair, title: 'Forensics Workbench', desc: 'Metadata, file carving, and timeline correlation' },
  { to: '/ctf/crypto', icon: Lock, title: 'Crypto Toolkit', desc: 'Ciphers, hashes, and text transformations' },
  { to: '/ctf/re', icon: Cpu, title: 'Reverse Engineering', desc: 'Binary analysis, strings, and entropy visualization' },
  { to: '/ctf/competition', icon: Shield, title: 'Competition Mode', desc: 'Team collaboration, flag tracking, and evidence board' },
];

export function CtfHubPage() {
  return (
    <div className="p-8">
      <div className="mb-8 flex items-center gap-3">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-600 shadow-lg shadow-indigo-200">
          <Trophy className="h-6 w-6 text-white" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-gray-900">CTF Assistant & Recon Hub</h1>
          <p className="text-gray-500">Your central command for Capture The Flag and Reconnaissance</p>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {modules.map(({ to, icon: Icon, title, desc }) => (
          <Link
            key={to}
            to={to}
            className="group relative flex flex-col rounded-2xl border border-gray-100 bg-white p-6 shadow-sm transition-all hover:shadow-md hover:border-indigo-100"
          >
            <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-50 text-indigo-600 transition-colors group-hover:bg-indigo-600 group-hover:text-white">
              <Icon className="h-5 w-5" />
            </div>
            <h3 className="mb-2 text-lg font-semibold text-gray-900">{title}</h3>
            <p className="text-sm text-gray-500 leading-relaxed flex-1">{desc}</p>
            <div className="mt-4 flex items-center text-sm font-medium text-indigo-600 opacity-0 transition-opacity group-hover:opacity-100">
              Launch Module &rarr;
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
