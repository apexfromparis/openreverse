import React, { useState } from 'react';
import { Copy, Check, Star, Search } from 'lucide-react';
import type { PluginItem } from '../types';

const PLUGINS: PluginItem[] = [
  {
    id: 'anti-debug-nuke',
    author: '@community/anti-debug-nuke',
    title: 'Anti-Debug & PEB Trap Nuke',
    description: 'Scans target process memory for RDTSC timing loops, PEB BeingDebugged flags, and hardware breakpoint traps, replacing them with NOPs.',
    category: 'Security',
    tier: 'PRO',
    installs: '2.4k',
    installCommand: '/install @community/anti-debug-nuke'
  },
  {
    id: 'crackme-sandbox-shield',
    author: '@community/crackme-sandbox-shield',
    title: 'Crackme Sandbox Shield',
    description: 'Hooks filesystem and registry Windows APIs to shield your physical machine against wiper malware or destructive crackme challenges.',
    category: 'Security',
    tier: 'PRO',
    installs: '5.8k',
    installCommand: '/install @community/crackme-sandbox-shield'
  },
  {
    id: 'kernel-driver-byovd',
    author: '@community/kernel-driver-byovd',
    title: 'Kernel Driver BYOVD Scanner',
    description: 'Audits .sys Windows kernel drivers for Bring Your Own Vulnerable Driver (BYOVD) IOCTL dispatch table flaws and privilege escalation primitives.',
    category: 'Kernel',
    tier: 'CREATOR',
    installs: '1.9k',
    installCommand: '/install @community/kernel-driver-byovd'
  },
  {
    id: 'auto-ctf-flag-solver',
    author: '@community/auto-ctf-flag-solver',
    title: 'Auto CTF Flag Solver Agent',
    description: 'Autonomous symbolic execution & XOR key brute-forcer that solves crackme challenges and dumps decrypted ASCII flags.',
    category: 'Crackme',
    tier: 'PRO',
    installs: '3.1k',
    installCommand: '/install @community/auto-ctf-flag-solver'
  }
];

export const HubMarketplace: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredPlugins = PLUGINS.filter(p => {
    const matchesCat = selectedCategory === 'All' || p.category === selectedCategory;
    const matchesSearch = p.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          p.author.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          p.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCat && matchesSearch;
  });

  const handleCopyCmd = (cmd: string, id: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  return (
    <section id="cloud-hub" className="py-20 px-6 max-w-6xl mx-auto">
      <div className="text-center max-w-2xl mx-auto mb-12">
        <span className="text-xs font-mono text-[#a1a1aa] tracking-widest uppercase block mb-2">
          OPENREVERSE DEV COMMUNITY (OpenReverse Cloud)
        </span>
        <h2 className="text-3xl md:text-4xl font-bold tracking-tight text-white mb-4">
          Community-Powered Plugin Hub.
        </h2>
        <p className="text-[#a1a1aa] text-sm mb-4">
          Extend your IDE with 1-click community plugins. Created by security researchers and reverse engineers, with 70% revenue share for Pro Creators.
        </p>
        <div className="inline-block bg-[#18181b] border border-[#fb923c]/40 px-3 py-1.5 rounded-md text-xs font-mono text-[#fb923c]">
          ⚡ Note: Installing plugins via <code>/install</code> requires a <strong>Pro Analyst</strong> subscription or above.
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mb-8">
        <div className="flex items-center gap-1 bg-[#09090b] border border-[#27272a] p-1 rounded-md">
          {['All', 'Security', 'Kernel', 'Crackme'].map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`text-xs font-mono px-3 py-1.5 rounded transition-colors ${
                selectedCategory === cat
                  ? 'bg-[#18181b] text-white font-semibold'
                  : 'text-[#71717a] hover:text-[#a1a1aa]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#71717a]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search plugins..."
            className="w-full bg-[#09090b] border border-[#27272a] rounded-md pl-9 pr-3 py-1.5 text-xs font-mono text-white outline-none placeholder-[#52525b] focus:border-[#3f3f46]"
          />
        </div>
      </div>

      {/* Plugins Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {filteredPlugins.map(plugin => (
          <div key={plugin.id} className="minimal-card p-6 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-mono text-white font-semibold">{plugin.author}</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold ${
                  plugin.tier === 'FREE'
                    ? 'bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30'
                    : plugin.tier === 'PRO'
                    ? 'bg-[#fb923c]/15 text-[#fb923c] border border-[#fb923c]/30'
                    : 'bg-white/10 text-white border border-white/20'
                }`}>
                  {plugin.tier}
                </span>
              </div>

              <h3 className="text-lg font-bold text-white mb-2">{plugin.title}</h3>
              <p className="text-xs text-[#a1a1aa] leading-relaxed mb-6">{plugin.description}</p>
            </div>

            <div className="flex items-center justify-between bg-black/60 p-2.5 rounded border border-[#27272a]">
              <code className="text-xs font-mono text-[#a1a1aa] truncate mr-2">
                {plugin.installCommand}
              </code>

              <div className="flex items-center gap-3">
                <span className="text-[11px] font-mono text-[#71717a] flex items-center gap-1">
                  <Star className="w-3 h-3 text-[#fb923c]" />
                  {plugin.installs}
                </span>

                <button
                  onClick={() => handleCopyCmd(plugin.installCommand, plugin.id)}
                  className="btn btn-ghost p-1.5 text-xs"
                  title="Copy install command"
                >
                  {copiedId === plugin.id ? (
                    <Check className="w-3.5 h-3.5 text-[#34d399]" />
                  ) : (
                    <Copy className="w-3.5 h-3.5 text-[#a1a1aa]" />
                  )}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
};
