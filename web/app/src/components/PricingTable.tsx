import React, { useState } from 'react';
import { Check } from 'lucide-react';

interface PricingTableProps {
  onOpenAuthModal: () => void;
}

export const PricingTable: React.FC<PricingTableProps> = ({ onOpenAuthModal }) => {
  const [isAnnual, setIsAnnual] = useState<boolean>(true);

  return (
    <section id="pricing" className="py-20 px-6 max-w-6xl mx-auto">
      <div className="text-center max-w-2xl mx-auto mb-12">
        <span className="text-xs font-mono text-[#a1a1aa] tracking-widest uppercase block mb-2">
          OPEN-CORE HYBRID PRICING
        </span>
        <h2 className="text-3xl md:text-4xl font-bold tracking-tight text-white mb-4">
          Transparent tiers for solo REs &amp; Red Teams.
        </h2>
        <p className="text-[#a1a1aa] text-sm">
          Always free with local Ollama models. Upgrade to OpenReverse Cloud Cloud for zero-latency GPT-4o, Claude 3.5 Sonnet, and Creator Marketplace publishing rights.
        </p>

        {/* Annual Toggle */}
        <div className="inline-flex items-center gap-3 mt-6 bg-[#09090b] border border-[#27272a] p-1.5 rounded-full">
          <button
            onClick={() => setIsAnnual(false)}
            className={`text-xs font-mono px-4 py-1 rounded-full transition-colors ${
              !isAnnual ? 'bg-[#18181b] text-white font-semibold' : 'text-[#71717a]'
            }`}
          >
            Monthly
          </button>
          <button
            onClick={() => setIsAnnual(true)}
            className={`text-xs font-mono px-4 py-1 rounded-full transition-colors ${
              isAnnual ? 'bg-[#18181b] text-white font-semibold' : 'text-[#71717a]'
            }`}
          >
            Annual <span className="text-[#34d399] ml-1">(Save 20%)</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
        {/* Community Free */}
        <div className="minimal-card p-8 flex flex-col justify-between">
          <div>
            <h3 className="text-xl font-bold text-white mb-1">Community Free</h3>
            <div className="text-4xl font-extrabold text-white my-4">
              $0 <span className="text-xs font-mono text-[#71717a] font-normal">/forever</span>
            </div>
            <p className="text-xs text-[#a1a1aa] mb-6">100% offline reverse engineering with local Ollama.</p>

            <ul className="space-y-3 text-xs text-[#a1a1aa] mb-8">
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Full Windows IDE &amp; Interactive TUI Shell</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Unlimited Local Ollama (qwen2.5-coder, deepseek-r1)</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Offline Driver (.sys) &amp; PE32+ static parser</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Basic Hex-Rays assembly decompilation</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#71717a] shrink-0" />
                <span className="text-[#71717a]">Browse OpenReverse Cloud Community Hub (Plugin installation requires Pro Analyst)</span>
              </li>
            </ul>
          </div>

          <a
            href="../../OpenReverse_Studio_Setup_v2.0.exe"
            download="OpenReverse_Studio_Setup_v2.0.exe"
            className="btn btn-secondary w-full text-center"
          >
            Download Free Studio
          </a>
        </div>

        {/* Pro Analyst */}
        <div className="minimal-card p-8 flex flex-col justify-between border-white/20 relative">
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-white text-black font-mono text-[10px] font-extrabold px-3 py-0.5 rounded-full uppercase tracking-wider">
            Most Popular
          </div>

          <div>
            <h3 className="text-xl font-bold text-white mb-1">Pro Analyst</h3>
            <div className="text-4xl font-extrabold text-white my-4">
              ${isAnnual ? '29' : '35'} <span className="text-xs font-mono text-[#71717a] font-normal">/month</span>
            </div>
            <p className="text-xs text-[#a1a1aa] mb-6">Zero-latency OpenReverse Cloud Cloud AI &amp; automated triage.</p>

            <ul className="space-y-3 text-xs text-[#a1a1aa] mb-8">
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span className="text-white font-medium">Everything in Community Free</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Unlimited OpenReverse Cloud Cloud (Claude 3.5 Sonnet, GPT-4o)</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span className="text-white font-semibold">✨ Install &amp; execute all OpenReverse Cloud Community Hub plugins</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Automated <code>/triage</code> with MITRE ATT&amp;CK Matrix</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Global AI symbol &amp; struct type inference (<code>/auto-rename</code>)</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Automated Vulnerability Audits (<code>/vuln</code>)</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Access to all OpenReverse Cloud PRO Community plugins</span>
              </li>
            </ul>
          </div>

          <button
            onClick={onOpenAuthModal}
            className="btn btn-primary w-full"
          >
            Sign Up with GitHub / Google
          </button>
        </div>

        {/* Dev Creator Pro */}
        <div className="minimal-card p-8 flex flex-col justify-between">
          <div>
            <h3 className="text-xl font-bold text-white mb-1">Dev Creator Pro</h3>
            <div className="text-4xl font-extrabold text-white my-4">
              ${isAnnual ? '79' : '99'} <span className="text-xs font-mono text-[#71717a] font-normal">/month</span>
            </div>
            <p className="text-xs text-[#a1a1aa] mb-6">For plugin developers &amp; security tool builders.</p>

            <ul className="space-y-3 text-xs text-[#a1a1aa] mb-8">
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span className="text-white font-medium">Everything in Pro Analyst</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Unlocked DEV CREATOR STUDIO GUI tab in IDE</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>C++ / Python / Lua Plugin SDK &amp; memory hooks</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Publish plugins to OpenReverse Cloud Hub (<code>/hub</code>)</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span className="text-[#34d399] font-medium">70% Revenue Share when Pro analysts use your plugins</span>
              </li>
              <li className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#34d399] shrink-0" />
                <span>Dedicated malware cloud sandbox testing</span>
              </li>
            </ul>
          </div>

          <button
            onClick={onOpenAuthModal}
            className="btn btn-secondary w-full"
          >
            Become a Dev Creator
          </button>
        </div>
      </div>
    </section>
  );
};
