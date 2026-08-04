import React, { useState } from 'react';
import { Code2 } from 'lucide-react';

export const DecompilerDiff: React.FC = () => {
  const [activeAddr] = useState<string>('0x140001230');

  return (
    <section id="hex-rays-ai" className="py-20 px-6 max-w-6xl mx-auto">
      <div className="text-center max-w-2xl mx-auto mb-12">
        <span className="text-xs font-mono text-[#a1a1aa] tracking-widest uppercase block mb-2">
          HEX-RAYS AI DECOMPILER ENGINE
        </span>
        <h2 className="text-3xl md:text-4xl font-bold tracking-tight text-white mb-4">
          Assembly to readable C++ in real time.
        </h2>
        <p className="text-[#a1a1aa] text-sm">
          Compare raw Capstone x64 machine instructions against OpenReverse's synthesized AST pseudocode. Includes automatic type inference and vulnerability highlighting.
        </p>
      </div>

      <div className="minimal-card p-6 grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
        {/* Left Pane: Raw x64 Assembly */}
        <div className="bg-black/60 rounded-lg p-5 border border-[#27272a] flex flex-col">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-[#27272a]">
            <div className="flex items-center gap-2 text-xs font-mono text-[#a1a1aa]">
              <Code2 className="w-4 h-4 text-white" />
              <span>x64 / PE32+ Disassembly</span>
            </div>
            <span className="text-[11px] font-mono bg-[#18181b] border border-[#27272a] text-[#a1a1aa] px-2 py-0.5 rounded">
              {activeAddr}
            </span>
          </div>

          <pre className="font-mono text-xs leading-relaxed overflow-x-auto text-[#a1a1aa] flex-1">
            <code>
              <span className="text-[#52525b]">0x140001230:</span>  <span className="text-white font-bold">sub</span>     <span className="text-[#fb923c]">rsp</span>, 28h{'\n'}
              <span className="text-[#52525b]">0x140001234:</span>  <span className="text-white font-bold">mov</span>     <span className="text-[#fb923c]">rax</span>, [rcx+8]{'\n'}
              <span className="text-[#52525b]">0x140001238:</span>  <span className="text-white font-bold">test</span>    <span className="text-[#fb923c]">rax</span>, rax{'\n'}
              <span className="text-[#52525b]">0x14000123B:</span>  <span className="text-white font-bold">jz</span>      <span className="text-[#a1a1aa]">short loc_140001250</span>{'\n'}
              <span className="text-[#52525b]">0x14000123D:</span>  <span className="text-white font-bold">lea</span>     <span className="text-[#fb923c]">rdx</span>, [rax+10h]{'\n'}
              <span className="text-[#52525b]">0x140001241:</span>  <span className="text-white font-bold">call</span>    <span className="text-[#34d399] font-bold">cs:IsDebuggerPresent</span>{'\n'}
              <span className="text-[#52525b]">0x140001247:</span>  <span className="text-white font-bold">test</span>    <span className="text-[#fb923c]">eax</span>, eax{'\n'}
              <span className="text-[#52525b]">0x140001249:</span>  <span className="text-white font-bold">jnz</span>     <span className="text-[#f87171]">short loc_terminate</span>{'\n'}
              <span className="text-[#52525b]">0x14000124B:</span>  <span className="text-white font-bold">mov</span>     <span className="text-[#fb923c]">eax</span>, 1{'\n'}
              <span className="text-[#52525b]">0x140001250:</span>  <span className="text-white font-bold">add</span>     <span className="text-[#fb923c]">rsp</span>, 28h{'\n'}
              <span className="text-[#52525b]">0x140001254:</span>  <span className="text-white font-bold">ret</span>
            </code>
          </pre>
        </div>

        {/* Right Pane: AI Hex-Rays C++ Pseudocode */}
        <div className="bg-black/60 rounded-lg p-5 border border-[#27272a] flex flex-col">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-[#27272a]">
            <div className="flex items-center gap-2 text-xs font-mono text-[#a1a1aa]">
              <span className="w-2 h-2 rounded-full bg-[#34d399]" />
              <span>AI Synthesized C++ Pseudocode</span>
            </div>
            <span className="text-[11px] font-mono bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30 px-2 py-0.5 rounded">
              AST Restored
            </span>
          </div>

          <pre className="font-mono text-xs leading-relaxed overflow-x-auto text-[#a1a1aa] flex-1">
            <code>
              <span className="text-[#fb923c] font-bold">bool</span> <span className="text-[#34d399] font-bold">VerifyLicenseAndSecurity</span>(<span className="text-white">LicenseContext</span>* <span className="text-[#fb923c]">ctx</span>) {'{'}{'\n'}
              {'    '}<span className="text-[#fb923c] font-bold">if</span> (!ctx || !ctx-&gt;keyBuffer) {'{'}{'\n'}
              {'        '}<span className="text-[#fb923c] font-bold">return</span> <span className="text-[#38bdf8]">false</span>;{'\n'}
              {'    '}{'}'}{'\n'}
              {'\n'}
              {'    '}<span className="text-[#71717a] italic">// [AI Alert] Anti-Debug heuristic check detected:</span>{'\n'}
              {'    '}<span className="text-[#fb923c] font-bold">if</span> (<span className="text-[#34d399] font-bold">IsDebuggerPresent</span>()) {'{'}{'\n'}
              {'        '}<span className="text-[#34d399]">TerminateProcess</span>(<span className="text-[#34d399]">GetCurrentProcess</span>(), <span className="text-[#38bdf8]">0xDEADCODE</span>);{'\n'}
              {'        '}<span className="text-[#fb923c] font-bold">return</span> <span className="text-[#38bdf8]">false</span>;{'\n'}
              {'    '}{'}'}{'\n'}
              {'\n'}
              {'    '}<span className="text-[#fb923c] font-bold">return</span> <span className="text-[#34d399] font-bold">VerifySignature</span>(ctx-&gt;keyBuffer + 0x10);{'\n'}
              {'}'}
            </code>
          </pre>
        </div>
      </div>
    </section>
  );
};
