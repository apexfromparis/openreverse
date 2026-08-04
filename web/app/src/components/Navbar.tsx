import React from 'react';
import { Terminal, Key, Download } from 'lucide-react';
import type { UserAuth } from '../types';

interface NavbarProps {
  auth: UserAuth;
  onOpenAuthModal: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ auth, onOpenAuthModal }) => {
  return (
    <header className="fixed top-0 left-0 right-0 h-16 bg-black/80 backdrop-blur-md border-b border-[#27272a] z-50 flex items-center">
      <div className="max-w-7xl w-full mx-auto px-6 flex items-center justify-between">
        {/* Brand Logo */}
        <a href="#" className="flex items-center gap-3 text-white no-underline">
          <div className="w-8 h-8 rounded-md bg-[#18181b] border border-[#3f3f46] flex items-center justify-center text-white">
            <Terminal className="w-4 h-4" />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-bold tracking-tight text-lg">OpenReverse</span>
            <span className="text-[11px] font-mono bg-[#18181b] border border-[#27272a] text-[#a1a1aa] px-1.5 py-0.5 rounded">
              v2.0.0
            </span>
          </div>
        </a>

        {/* Navigation Links */}
        <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-[#a1a1aa]">
          <a href="#features" className="hover:text-white transition-colors">Features</a>
          <a href="#AI-assisted-shell" className="hover:text-white transition-colors">AI-assisted Shell</a>
          <a href="#hex-rays-ai" className="hover:text-white transition-colors">Hex-Rays AI</a>
          <a href="#cloud-hub" className="hover:text-white transition-colors">OpenReverse Cloud Hub</a>
          <a href="#pricing" className="hover:text-white transition-colors">Pricing</a>
        </nav>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          <button
            onClick={onOpenAuthModal}
            className="group relative inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#121215] border border-[#27272a] hover:border-[#3f3f46] text-xs font-medium text-[#a1a1aa] hover:text-white transition-all duration-200 shadow-sm"
          >
            {auth.isLoggedIn ? (
              <>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="font-mono text-white font-semibold">{auth.username}</span>
                <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-[#18181b] text-[#a1a1aa] border border-[#27272a]">Pro</span>
              </>
            ) : (
              <>
                <Key className="w-3.5 h-3.5 text-[#a1a1aa] group-hover:text-white transition-colors" />
                <span>Sign In</span>
              </>
            )}
          </button>

          <a
            href="../../OpenReverse_Studio_Setup_v2.0.exe"
            download="OpenReverse_Studio_Setup_v2.0.exe"
            className="btn btn-primary text-xs"
          >
            <Download className="w-4 h-4" />
            <span>Download .exe</span>
          </a>
        </div>
      </div>
    </header>
  );
};
