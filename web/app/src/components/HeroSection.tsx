import React from 'react';
import { Terminal, Download, ShieldCheck, Zap, Key } from 'lucide-react';

interface HeroSectionProps {
  onScrollToTerminal: () => void;
  onOpenAuthModal: () => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({ onScrollToTerminal, onOpenAuthModal }) => {
  return (
    <section className="pt-36 pb-20 px-6 relative z-10 max-w-5xl mx-auto text-center">
      {/* Minimalist Top Badge */}
      <div className="inline-flex items-center gap-2.5 px-3 py-1.5 rounded-full bg-[#18181b] border border-[#27272a] text-[#a1a1aa] font-mono text-xs mb-8">
        <span className="pulse-dot" />
        <span className="tracking-wider">OPENREVERSE 2.0 — REVERSE ENGINEERING &amp; ANALYSIS</span>
      </div>

      {/* Bold Monochrome Hero Title */}
      <h1 className="text-4xl md:text-6xl lg:text-7xl font-extrabold tracking-tight leading-[1.08] text-white mb-6">
        The AI-assisted Reverse <br className="hidden md:inline" />
        <span className="text-[#a1a1aa]">Engineering Suite.</span>
      </h1>

      {/* Hero Subtitle */}
      <p className="text-lg md:text-xl text-[#a1a1aa] max-w-2xl mx-auto mb-10 leading-relaxed font-normal">
        Inspired by modern developer tools like OpenCode. Combine automated Hex-Rays C++ decompilation, global AI symbol inference, and automated threat triage in a native Windows Studio.
      </p>

      {/* Action Buttons */}
      <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
        <a
          href="../../OpenReverse_Studio_Setup_v2.0.exe"
          download="OpenReverse_Studio_Setup_v2.0.exe"
          className="btn btn-primary btn-lg w-full sm:w-auto"
        >
          <Download className="w-4 h-4" />
          <span>Download Windows Setup (.exe)</span>
          <span className="text-[11px] font-mono opacity-60 ml-1">v2.0 • 8.9 MB</span>
        </a>

        <button
          onClick={onScrollToTerminal}
          className="btn btn-secondary btn-lg w-full sm:w-auto"
        >
          <Terminal className="w-4 h-4 text-[#a1a1aa]" />
          <span>Try AI-assisted Shell in Browser</span>
          <kbd className="ml-2 font-mono">/</kbd>
        </button>

        <button
          onClick={onOpenAuthModal}
          className="btn btn-ghost btn-lg w-full sm:w-auto"
        >
          <Key className="w-4 h-4 text-[#a1a1aa]" />
          <span>Supabase Account</span>
        </button>
      </div>

      {/* Quick Spec Highlights */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-left max-w-4xl mx-auto pt-6 border-t border-[#27272a]">
        <div className="p-4 minimal-card">
          <div className="flex items-center gap-2 text-white font-semibold text-sm mb-1">
            <Zap className="w-4 h-4 text-[#38bdf8]" />
            <span>AI Automated Threat Triage</span>
          </div>
          <p className="text-xs text-[#a1a1aa]">
            Automated MITRE ATT&amp;CK mapping and threat score (0–100) on any target binary.
          </p>
        </div>

        <div className="p-4 minimal-card">
          <div className="flex items-center gap-2 text-white font-semibold text-sm mb-1">
            <Terminal className="w-4 h-4 text-[#34d399]" />
            <span>100% Offline / OpenReverse Cloud Cloud</span>
          </div>
          <p className="text-xs text-[#a1a1aa]">
            Runs locally with Ollama (qwen2.5-coder) or connects to OpenReverse Cloud cloud clusters.
          </p>
        </div>

        <div className="p-4 minimal-card">
          <div className="flex items-center gap-2 text-white font-semibold text-sm mb-1">
            <ShieldCheck className="w-4 h-4 text-[#fb923c]" />
            <span>Driver (.sys) &amp; PE Parity</span>
          </div>
          <p className="text-xs text-[#a1a1aa]">
            Analyze kernel drivers and executables statically from disk or attach live to PIDs.
          </p>
        </div>
      </div>
    </section>
  );
};
