import React from 'react';
import { Terminal } from 'lucide-react';

interface FooterProps {
  onOpenAuthModal: () => void;
}

export const Footer: React.FC<FooterProps> = ({ onOpenAuthModal }) => {
  return (
    <footer className="bg-[#040406] border-t border-[#27272a] py-16 px-6 z-10 relative">
      <div className="max-w-6xl mx-auto flex flex-col md:flex-row justify-between gap-12 mb-12">
        <div className="max-w-xs">
          <div className="flex items-center gap-2 text-white font-bold tracking-tight text-lg mb-4">
            <Terminal className="w-5 h-5" />
            <span>OpenReverse</span>
            <span className="text-[11px] font-mono bg-[#18181b] border border-[#27272a] text-[#a1a1aa] px-1.5 py-0.5 rounded">
              v2.0.0
            </span>
          </div>
          <p className="text-xs text-[#a1a1aa] leading-relaxed">
            An AI-assisted reverse-engineering workbench for Windows.
          </p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 gap-10 text-xs">
          <div className="flex flex-col gap-2.5">
            <h5 className="font-mono text-white uppercase tracking-wider text-[11px] font-bold">Platform</h5>
            <a href="#AI-assisted-shell" className="text-[#a1a1aa] hover:text-white transition-colors">AI Triage</a>
            <a href="#hex-rays-ai" className="text-[#a1a1aa] hover:text-white transition-colors">Hex-Rays Decompiler</a>
            <a href="#AI-assisted-shell" className="text-[#a1a1aa] hover:text-white transition-colors">AI-assisted Shell</a>
          </div>

          <div className="flex flex-col gap-2.5">
            <h5 className="font-mono text-white uppercase tracking-wider text-[11px] font-bold">Ecosystem</h5>
            <a href="#cloud-hub" className="text-[#a1a1aa] hover:text-white transition-colors">OpenReverse Cloud Hub</a>
            <a href="#pricing" className="text-[#a1a1aa] hover:text-white transition-colors">Pricing &amp; Tiers</a>
            <a href="../../OpenReverse_Studio_Setup_v2.0.exe" download className="text-[#a1a1aa] hover:text-white transition-colors">Windows Setup</a>
          </div>

          <div className="flex flex-col gap-2.5">
            <h5 className="font-mono text-white uppercase tracking-wider text-[11px] font-bold">Account (Supabase)</h5>
            <button onClick={onOpenAuthModal} className="text-left text-[#a1a1aa] hover:text-white transition-colors">GitHub OAuth</button>
            <button onClick={onOpenAuthModal} className="text-left text-[#a1a1aa] hover:text-white transition-colors">Google OAuth</button>
            <button onClick={onOpenAuthModal} className="text-left text-[#a1a1aa] hover:text-white transition-colors">License Token</button>
          </div>
        </div>
      </div>

      <div className="max-w-6xl mx-auto pt-8 border-t border-[#27272a] flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#71717a]">
        <span>© 2026 OpenReverse Studio • Apex (@apexfromparis). All rights reserved.</span>
        <div className="flex items-center gap-2 text-[#34d399] font-mono">
          <span className="w-2 h-2 rounded-full bg-[#34d399]" />
          <span>OpenReverse Cloud Cloud Cluster Online</span>
        </div>
      </div>
    </footer>
  );
};
